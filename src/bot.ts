import { Telegraf } from "telegraf";
import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

const bot = new Telegraf(process.env.BOT_TOKEN as string);
const API_BASE = process.env.COPPERX_API_BASE || "https://income-api.copperx.io";

interface UserSession {
  email?: string;
  otpSent?: boolean;
  sid?: string;
  token?: string;
}

const userSessions: Record<number, UserSession> = {};

// 📌 Command: /start
bot.start((ctx) => {
  ctx.reply("🚀 Welcome to the Copperx Payout Bot! Use /help to see the available commands.");
});

// 📌 Command: /login <email>
bot.command("login", async (ctx) => {
  const chatId = ctx.chat.id;
  const messageParts = ctx.message.text.split(" ");

  if (messageParts.length < 2) {
    ctx.reply("❌ You must provide an email. Example: `/login your@email.com`");
    return;
  }

  const email = messageParts[1];
  ctx.reply(`🔐 Sending OTP code to ${email}...`);

  try {
    const response = await axios.post(`${API_BASE}/api/auth/email-otp/request`, { email });

    console.log("✅ API Response for OTP request:", response.data);

    if (response.status === 201 || response.status === 200) {
      userSessions[chatId] = { 
        email, 
        otpSent: true, 
        sid: response.data.sid  
      };

      console.log(`📌 SID stored for ${chatId}: ${response.data.sid}`); 

      ctx.reply("📩 OTP code sent. Please enter the code using `/otp <code>`.");
    } else {
      ctx.reply("⚠️ Could not send OTP. Please try again later.");
    }
  } catch (error:any) {
    console.error("❌ Error requesting OTP:", error.response?.data || error.message);
    ctx.reply("❌ Failed to send OTP. Please check your email and try again.");
  }
});

// 📌 Command: /otp <code>
bot.command("otp", async (ctx) => {
  const chatId = ctx.chat.id;
  const messageParts = ctx.message.text.split(" ");

  if (!userSessions[chatId] || !userSessions[chatId].otpSent || !userSessions[chatId].sid) {
    ctx.reply("⚠️ You haven't requested an OTP. Use `/login <email>` first.");
    console.log(`🔴 No OTP session found for ${chatId}`);
    return;
  }

  if (messageParts.length < 2) {
    ctx.reply("❌ You must provide the OTP code. Example: `/otp 123456`");
    return;
  }

  const otp = messageParts[1];
  const { email, sid } = userSessions[chatId];

  console.log(`🔍 Verifying OTP for ${email} with SID ${sid}`);

  ctx.reply("🔍 Verifying OTP code...");

  try {
    const response = await axios.post(`${API_BASE}/api/auth/email-otp/authenticate`, {
      email,
      otp,
      sid  
    });

    console.log("✅ API Response:", response.data); // 🔍 Mostrar la respuesta completa de la API

    // Ahora extraemos correctamente el token desde `response.data.accessToken`
    if (response.status === 200 && response.data.accessToken) {
      const token = response.data.accessToken;

      userSessions[chatId] = { 
        email, 
        otpSent: false, 
        token // 🔹 Guardamos el accessToken correctamente
      };

      console.log(`✅ Token stored for ${chatId}: ${token}`);  // Debugging

      ctx.reply("✅ Authentication successful! You can now use the wallet management commands.");
    } else {
      console.log("❌ Token not found in API response:", response.data);
      ctx.reply("⚠️ Authentication failed. Invalid or expired OTP.");
    }
  } catch (error:any) {
    console.error("❌ Error authenticating OTP:", error.response?.data || error.message);
    ctx.reply("❌ OTP authentication failed. Check the code and try again.");
  }
});




bot.command("balance", async (ctx) => {
  const chatId = ctx.chat.id;

  if (!userSessions[chatId] || !userSessions[chatId].token) {
    ctx.reply("⚠️ You are not logged in. Use `/login <email>` first.");
    return;
  }

  ctx.reply("🔍 Fetching your wallet balance...");

  try {
    const response = await axios.get(`${API_BASE}/api/wallets/balances`, {
      headers: {
        Authorization: `Bearer ${userSessions[chatId].token}`, // 🔹 Enviar el `accessToken` correctamente
      },
    });

    console.log("✅ Balance response:", response.data);  // Debugging

    const balances = response.data;
    let balanceMessage = "💰 **Your Wallet Balances:**\n\n";

    balances.forEach((wallet: any) => {
      balanceMessage += `🔹 **${wallet.network}**: ${wallet.balance} USDC\n`;
    });

    ctx.reply(balanceMessage);
  } catch (error:any) {
    console.error("❌ Error fetching balance:", error.response?.data || error.message);
    ctx.reply("❌ Could not retrieve balance. Please try again later.");
  }
});




bot.command("wallets", async (ctx) => {
  const chatId = ctx.chat.id;

  if (!userSessions[chatId] || !userSessions[chatId].token) {
    ctx.reply("⚠️ You are not logged in. Use `/login <email>` first.");
    return;
  }

  ctx.reply("🔍 Retrieving your wallets...");

  try {
    const response = await axios.get(`${API_BASE}/api/wallets`, {
      headers: {
        Authorization: `Bearer ${userSessions[chatId].token}`, // 🔹 Enviar el `accessToken` correctamente
      },
    });

    console.log("✅ Wallet response:", response.data);  // Debugging

    const wallets = response.data;
    let walletMessage = "🔐 **Your Wallets:**\n\n";

    wallets.forEach((wallet: any) => {
      walletMessage += `🆔 **ID:** ${wallet.id}\n🌐 **Network:** ${wallet.network}\n💳 **Address:** ${wallet.address}\n\n`;
    });

    ctx.reply(walletMessage);
  } catch (error:any) {
    console.error("❌ Error fetching wallets:", error.response?.data || error.message);
    ctx.reply("❌ Could not retrieve wallets. Please try again later.");
  }
});






// Start the bot
bot.launch().then(() => {
  console.log("🤖 Copperx Payout Bot (English Version) started...");
});
