import { NextRequest, NextResponse } from "next/server";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { createToken } from "@/lib/jwt";
import { md5 } from "@/lib/crypto";

export async function POST(request: NextRequest) {
	try {
		const body = (await request.json()) as { name?: string; password?: string };
		const { name, password } = body;

		if (!name || !password) {
			return NextResponse.json({ code: 400, message: "用户名和密码不能为空" }, { status: 400 });
		}

		const { env } = getCloudflareContext();
		const db = env.DB;

		const user = await db
			.prepare("SELECT id, name, last_login_time, last_login_ip, created_at FROM users WHERE name = ? AND password = ?")
			.bind(name, md5(password))
			.first<{ id: number; name: string; last_login_time: string | null; last_login_ip: string | null; created_at: string | null }>();

		if (!user) {
			return NextResponse.json({ code: 401, message: "用户名或密码错误" }, { status: 401 });
		}

		const now = new Date().toISOString();
		const ip = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "unknown";

		await db.prepare("UPDATE users SET last_login_time = ?, last_login_ip = ?, updated_at = ? WHERE id = ?").bind(now, ip, now, user.id).run();

		const token = await createToken({ id: user.id, name: user.name }, env.JWT_SECRET);

		return NextResponse.json({
			code: 0,
			message: "登录成功",
			data: {
				token,
				user: {
					id: user.id,
					name: user.name,
					lastLoginTime: user.last_login_time,
					lastLoginIp: user.last_login_ip,
					createdAt: user.created_at,
				},
			},
		});
	} catch (error) {
		console.error("Login error:", error);
		return NextResponse.json({ code: 500, message: "服务器内部错误" }, { status: 500 });
	}
}
