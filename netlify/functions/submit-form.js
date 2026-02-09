const fetch = require("node-fetch");

exports.handler = async (event) => {
  try {
    const body = JSON.parse(event.body || "{}");

    /* 🐝 Honeypot check */
    if (body["website_url"] || body["bot-field"]) {
      return { statusCode: 200, body: "OK" }; // silent drop
    }

    /* ⏱️ Timing check */
    const formTime = Number(body.form_time || 0);
    if (!formTime || Date.now() - formTime < 3000) {
      return { statusCode: 200, body: "OK" };
    }

    /* 🔗 Link spam check */
    const text = JSON.stringify(body).toLowerCase();
    const blocked = [
      "http://",
      "https://",
      "www.",
      ".com",
      ".net",
      ".org",
      "<a",
      "[url="
    ];

    if (blocked.some(p => text.includes(p))) {
      return { statusCode: 200, body: "OK" };
    }

    /* 🤖 reCAPTCHA verification */
    const token = body["g-recaptcha-response"];
    if (!token) {
      return { statusCode: 200, body: "OK" };
    }

    const verify = await fetch(
      "https://www.google.com/recaptcha/api/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `secret=${process.env.RECAPTCHA_SECRET}&response=${token}`
      }
    );

    const data = await verify.json();

    if (!data.success || data.score < 0.5) {
      return { statusCode: 200, body: "OK" };
    }

    /* ✅ Valid human — forward to Netlify Forms */
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString()
    };

  } catch (err) {
    return { statusCode: 200, body: "OK" };
  }
};
