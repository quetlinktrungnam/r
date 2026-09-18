const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      ...CORS
    }
  });
}

function cleanDeviceId(id) {
  return String(id || "").trim();
}

function validDeviceId(id) {
  return /^device_[a-zA-Z0-9-]{10,150}$/.test(id);
}

async function createSession(env) {
  const token =
    crypto.randomUUID().replaceAll("-", "") +
    crypto.randomUUID().replaceAll("-", "");

  await env.SESSIONS.put(
    `session:${token}`,
    "1",
    { expirationTtl: 3600 }
  );

  return token;
}

async function checkSession(request, env) {
  const auth = request.headers.get("Authorization") || "";

  if (!auth.startsWith("Bearer ")) {
    return false;
  }

  const token = auth.substring(7).trim();

  if (!token) {
    return false;
  }

  const value = await env.SESSIONS.get(`session:${token}`);

  return value === "1";
}

async function getAllDevices(env) {
  const devices = [];
  let cursor = undefined;

  while (true) {
    const result = await env.DEVICES.list({
      prefix: "device:",
      cursor
    });

    for (const key of result.keys) {
      const value = await env.DEVICES.get(key.name);

      if (!value) continue;

      try {
        devices.push(JSON.parse(value));
      } catch {}
    }

    if (result.list_complete) {
      break;
    }

    cursor = result.cursor;
  }

  devices.sort((a, b) => {
    return String(b.created_at || "").localeCompare(
      String(a.created_at || "")
    );
  });

  return devices;
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    /*
      ==========================================
      PUBLIC CHECK
      T.NAM dùng endpoint này
      ==========================================
    */

    if (path === "/check" && request.method === "GET") {
      const device = cleanDeviceId(
        url.searchParams.get("device")
      );

      if (!validDeviceId(device)) {
        return json({
          approved: false
        });
      }

      const data = await env.DEVICES.get(
        `device:${device}`
      );

      return json({
        approved: !!data
      });
    }

    /*
      ==========================================
      ADMIN LOGIN
      ==========================================
    */

    if (
      path === "/admin/login" &&
      request.method === "POST"
    ) {
      const body = await readBody(request);

      const password = String(
        body.password || ""
      );

      if (!env.ADMIN_PASSWORD) {
        return json({
          ok: false,
          message: "ADMIN_PASSWORD chưa được cấu hình."
        }, 500);
      }

      if (password !== env.ADMIN_PASSWORD) {
        return json({
          ok: false,
          message: "Mã truy cập không đúng."
        }, 401);
      }

      const token = await createSession(env);

      return json({
        ok: true,
        token,
        expires_in: 3600
      });
    }

    /*
      ==========================================
      TỪ ĐÂY TRỞ XUỐNG BẮT BUỘC ĐĂNG NHẬP
      ==========================================
    */

    const authenticated = await checkSession(
      request,
      env
    );

    if (!authenticated) {
      return json({
        ok: false,
        message: "Unauthorized"
      }, 401);
    }

    /*
      ==========================================
      DANH SÁCH
      GET /admin/devices
      ==========================================
    */

    if (
      path === "/admin/devices" &&
      request.method === "GET"
    ) {
      const devices = await getAllDevices(env);

      return json({
        ok: true,
        devices
      });
    }

    /*
      ==========================================
      THÊM MÃ
      POST /admin/devices
      ==========================================
    */

    if (
      path === "/admin/devices" &&
      request.method === "POST"
    ) {
      const body = await readBody(request);

      const id = cleanDeviceId(body.id);
      const note = String(body.note || "").trim();

      if (!validDeviceId(id)) {
        return json({
          ok: false,
          message: "Mã thiết bị không hợp lệ."
        }, 400);
      }

      const key = `device:${id}`;

      const exists = await env.DEVICES.get(key);

      if (exists) {
        return json({
          ok: false,
          message: "Thiết bị đã tồn tại."
        }, 409);
      }

      const item = {
        id,
        note,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      await env.DEVICES.put(
        key,
        JSON.stringify(item)
      );

      return json({
        ok: true,
        device: item
      });
    }

    /*
      ==========================================
      SỬA GHI CHÚ
      PUT /admin/devices/:id
      ==========================================
    */

    if (
      path.startsWith("/admin/devices/") &&
      request.method === "PUT"
    ) {
      const id = decodeURIComponent(
        path.substring("/admin/devices/".length)
      );

      if (!validDeviceId(id)) {
        return json({
          ok: false,
          message: "Mã thiết bị không hợp lệ."
        }, 400);
      }

      const key = `device:${id}`;

      const oldData = await env.DEVICES.get(key);

      if (!oldData) {
        return json({
          ok: false,
          message: "Không tìm thấy thiết bị."
        }, 404);
      }

      const body = await readBody(request);

      let oldItem;

      try {
        oldItem = JSON.parse(oldData);
      } catch {
        oldItem = {
          id,
          note: ""
        };
      }

      const item = {
        ...oldItem,
        id,
        note: String(body.note || "").trim(),
        updated_at: new Date().toISOString()
      };

      await env.DEVICES.put(
        key,
        JSON.stringify(item)
      );

      return json({
        ok: true,
        device: item
      });
    }

    /*
      ==========================================
      XÓA
      DELETE /admin/devices/:id
      ==========================================
    */

    if (
      path.startsWith("/admin/devices/") &&
      request.method === "DELETE"
    ) {
      const id = decodeURIComponent(
        path.substring("/admin/devices/".length)
      );

      if (!validDeviceId(id)) {
        return json({
          ok: false,
          message: "Mã thiết bị không hợp lệ."
        }, 400);
      }

      const key = `device:${id}`;

      const exists = await env.DEVICES.get(key);

      if (!exists) {
        return json({
          ok: false,
          message: "Thiết bị không tồn tại."
        }, 404);
      }

      await env.DEVICES.delete(key);

      return json({
        ok: true,
        message: "Đã xóa thiết bị."
      });
    }

    return json({
      ok: false,
      message: "Not Found"
    }, 404);
  }
};
