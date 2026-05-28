function base64UrlEncode(data: string): string {
	return btoa(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(data: string): string {
	const padded = data + "=".repeat((4 - (data.length % 4)) % 4);
	return atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
}

async function sign(payload: string, secret: string): Promise<string> {
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
	return base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
}

export async function createToken(data: Record<string, unknown>, secret: string, expiresInSeconds = 86400): Promise<string> {
	const header = { alg: "HS256", typ: "JWT" };
	const now = Math.floor(Date.now() / 1000);
	const payload = { ...data, iat: now, exp: now + expiresInSeconds };

	const encodedHeader = base64UrlEncode(JSON.stringify(header));
	const encodedPayload = base64UrlEncode(JSON.stringify(payload));
	const signature = await sign(`${encodedHeader}.${encodedPayload}`, secret);

	return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export async function verifyToken(token: string, secret: string): Promise<Record<string, unknown> | null> {
	try {
		const parts = token.split(".");
		if (parts.length !== 3) return null;

		const [encodedHeader, encodedPayload, signature] = parts;
		const expectedSignature = await sign(`${encodedHeader}.${encodedPayload}`, secret);

		if (signature !== expectedSignature) return null;

		const payload = JSON.parse(base64UrlDecode(encodedPayload));
		const now = Math.floor(Date.now() / 1000);

		if (payload.exp && payload.exp < now) return null;

		return payload;
	} catch {
		return null;
	}
}
