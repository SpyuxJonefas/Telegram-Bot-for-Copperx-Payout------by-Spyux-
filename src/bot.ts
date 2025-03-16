import { Telegraf } from "telegraf";
import axios from "axios";
import dotenv from "dotenv";
import Pusher from "pusher-js";

dotenv.config();

const bot = new Telegraf(process.env.BOT_TOKEN as string);
const API_BASE = process.env.COPPERX_API_BASE || "https://income-api.copperx.io";

// Definir estructura para almacenar datos temporales del usuario
interface UserSession {
  email?: string;
  token?: string;
  otpSent?: boolean;
  sid?: string;
  pendingTransfer?: {
    amount: number;
    asset: string;
    recipient: string;
  };
  pendingWithdrawal?: {  // 🔹 Agregamos la interfaz para retiros
    amount: number;
    asset: string;
    bankAccountId: string;
  };
}

// 📌 Objeto donde guardamos sesiones de usuarios
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
        Authorization: `Bearer ${userSessions[chatId].token}`,
      },
    });

    console.log("✅ Balance response:", JSON.stringify(response.data, null, 2));  // Debugging

    const balances = response.data;
    let balanceMessage = "💰 **Your Wallet Balances:**\n\n";

    if (!balances || balances.length === 0) {
      ctx.reply("🚨 **No assets found in your wallets. Your balance is 0 USDC.**");
      return;
    }

    balances.forEach((wallet: any) => {
      const network = wallet.network || "Unknown Network";
      let balanceText = `🌐 **${network}**\n`;

      if (wallet.balances && wallet.balances.length > 0) {
        wallet.balances.forEach((bal: any) => {
          console.log("🔍 Balance object:", JSON.stringify(bal, null, 2));  

          const asset = bal.symbol || "Unknown Asset"; // 🔹 Usamos `symbol` en lugar de `asset`
          const amount = bal.balance !== undefined ? bal.balance : "0"; // 🔹 Usamos `balance` en lugar de `amount`

          balanceText += `🔹 **${asset}**: ${amount}\n`;
        });
      } else {
        balanceText += "🔹 **No assets found in this wallet**\n";
      }

      balanceMessage += `${balanceText}\n`;
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
      const walletId = wallet.id || "Unknown ID";
      const network = wallet.network || "Unknown Network";
      const address = wallet.walletAddress !== undefined ? wallet.walletAddress : "No Address Available"; // 🔹 Corregimos aquí

      walletMessage += `🆔 **ID:** ${walletId}\n🌐 **Network:** ${network}\n💳 **Address:** ${address}\n\n`;
    });

    ctx.reply(walletMessage);
  } catch (error:any) {
    console.error("❌ Error fetching wallets:", error.response?.data || error.message);
    ctx.reply("❌ Could not retrieve wallets. Please try again later.");
  }
});

bot.command("send", async (ctx) => {
  const chatId = ctx.chat.id;
  const messageParts = ctx.message.text.split(" ");

  // 📌 Verificamos que el usuario está autenticado
  if (!userSessions[chatId] || !userSessions[chatId].token) {
    ctx.reply("⚠️ You are not logged in. Use `/login <email>` first.");
    return;
  }

  // 📌 Validamos los parámetros del comando
  if (messageParts.length < 4) {
    ctx.reply("❌ Invalid command format. Use:\n`/send <amount> <asset> <recipient>`");
    return;
  }

  const amount = parseFloat(messageParts[1]);
  const asset = messageParts[2].toUpperCase();
  const recipient = messageParts[3];

  // 📌 Validamos monto y activo
  if (isNaN(amount) || amount <= 0) {
    ctx.reply("❌ Amount must be a valid number greater than 0.");
    return;
  }

  // 📌 Activos permitidos (se pueden agregar más si es necesario)
  const allowedAssets = ["USDC", "STRK"];
  if (!allowedAssets.includes(asset)) {
    ctx.reply(`❌ Unsupported asset: ${asset}. Only ${allowedAssets.join(", ")} are allowed.`);
    return;
  }

  // 📌 Validamos si el destinatario es email o wallet
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const walletRegex = /^0x[a-fA-F0-9]{40}$/;

  if (!emailRegex.test(recipient) && !walletRegex.test(recipient)) {
    ctx.reply("❌ Invalid recipient. Must be a valid email or wallet address.");
    return;
  }

  // 📌 Confirmación antes de enviar
  ctx.reply(`⚠️ **Confirm Transaction**\n\n💸 **Amount:** ${amount} ${asset}\n🎯 **Recipient:** ${recipient}\n\nReply with **/confirm** to proceed.`);

  // Guardamos la transacción en sesión temporal
  userSessions[chatId].pendingTransfer = { amount, asset, recipient };
});

bot.command("confirm", async (ctx) => {
  const chatId = ctx.chat.id;

  // 📌 Verificamos que el usuario tiene una transacción pendiente
  if (!userSessions[chatId] || !userSessions[chatId].pendingTransfer) {
    ctx.reply("⚠️ No pending transaction. Use `/send` first.");
    return;
  }

  const { amount, asset, recipient } = userSessions[chatId].pendingTransfer;

  ctx.reply("⏳ Processing your transaction...");

  try {
    const response = await axios.post(
      `${API_BASE}/api/transfers/send`,
      { amount, asset, recipient },
      { headers: { Authorization: `Bearer ${userSessions[chatId].token}` } }
    );

    console.log("✅ Transfer response:", response.data);

    ctx.reply(`✅ **Transaction Successful!**\n\n💸 **Amount:** ${amount} ${asset}\n🎯 **Recipient:** ${recipient}`);
    
    // Eliminamos la transacción pendiente
    delete userSessions[chatId].pendingTransfer;
  } catch (error:any) {
    console.error("❌ Error sending funds:", error.response?.data || error.message);
    ctx.reply("❌ Transaction failed. Please try again later.");
  }
});

bot.command("withdraw", async (ctx) => {
  const chatId = ctx.chat.id;
  const messageParts = ctx.message.text.split(" ");

  // 📌 Verificamos que el usuario está autenticado
  if (!userSessions[chatId] || !userSessions[chatId].token) {
    ctx.reply("⚠️ You are not logged in. Use `/login <email>` first.");
    return;
  }

  // 📌 Validamos los parámetros del comando
  if (messageParts.length < 4) {
    ctx.reply("❌ Invalid command format. Use:\n`/withdraw <amount> <asset> <bank_account_id>`");
    return;
  }

  const amount = parseFloat(messageParts[1]);
  const asset = messageParts[2].toUpperCase();
  const bankAccountId = messageParts[3];

  // 📌 Validamos monto y activo
  if (isNaN(amount) || amount <= 0) {
    ctx.reply("❌ Amount must be a valid number greater than 0.");
    return;
  }

  // 📌 Activos permitidos
  const allowedAssets = ["USDC", "STRK"];
  if (!allowedAssets.includes(asset)) {
    ctx.reply(`❌ Unsupported asset: ${asset}. Only ${allowedAssets.join(", ")} are allowed.`);
    return;
  }

  // 📌 Validamos que el ID de la cuenta bancaria sea un número
  if (!/^\d+$/.test(bankAccountId)) {
    ctx.reply("❌ Invalid bank account ID. It must be a numeric value.");
    return;
  }

  // 📌 Confirmación antes de enviar
  ctx.reply(`⚠️ **Confirm Withdrawal**\n\n💸 **Amount:** ${amount} ${asset}\n🏦 **Bank Account ID:** ${bankAccountId}\n\nReply with **/confirmwithdraw** to proceed.`);

  // Guardamos la transacción en sesión temporal
  userSessions[chatId].pendingWithdrawal = { amount, asset, bankAccountId };
});

bot.command("confirmwithdraw", async (ctx) => {
  const chatId = ctx.chat.id;

  // 📌 Verificamos que el usuario tiene un retiro pendiente
  if (!userSessions[chatId] || !userSessions[chatId].pendingWithdrawal) {
    ctx.reply("⚠️ No pending withdrawal. Use `/withdraw` first.");
    return;
  }

  const { amount, asset, bankAccountId } = userSessions[chatId].pendingWithdrawal;

  ctx.reply("⏳ Processing your withdrawal...");

  try {
    const response = await axios.post(
      `${API_BASE}/api/transfers/offramp`,
      { amount, asset, bankAccountId },
      { headers: { Authorization: `Bearer ${userSessions[chatId].token}` } }
    );

    console.log("✅ Withdrawal response:", response.data);

    ctx.reply(`✅ **Withdrawal Successful!**\n\n💸 **Amount:** ${amount} ${asset}\n🏦 **Bank Account ID:** ${bankAccountId}`);
    
    // Eliminamos el retiro pendiente
    delete userSessions[chatId].pendingWithdrawal;
  } catch (error:any) {
    console.error("❌ Error processing withdrawal:", error.response?.data || error.message);
    ctx.reply("❌ Withdrawal failed. Please try again later.");
  }
});

bot.command("history", async (ctx) => {
  const chatId = ctx.chat.id;

  // 📌 Verificamos que el usuario está autenticado
  if (!userSessions[chatId] || !userSessions[chatId].token) {
    ctx.reply("⚠️ You are not logged in. Use `/login <email>` first.");
    return;
  }

  ctx.reply("📊 Fetching your transaction history...");

  try {
    const response = await axios.get(`${API_BASE}/api/transfers?page=1&limit=10`, {
      headers: {
        Authorization: `Bearer ${userSessions[chatId].token}`,
      },
    });

    console.log("✅ History response:", response.data);  // Debugging

    const transactions = response.data;
    if (!transactions || transactions.length === 0) {
      ctx.reply("📭 No transactions found.");
      return;
    }

    let historyMessage = "📜 **Your Last 10 Transactions:**\n\n";

    transactions.forEach((tx: any) => {
      const date = new Date(tx.createdAt).toLocaleString();
      const amount = tx.amount;
      const asset = tx.asset;
      const type = tx.type.charAt(0).toUpperCase() + tx.type.slice(1); // Capitalize type
      const status = tx.status.charAt(0).toUpperCase() + tx.status.slice(1); // Capitalize status
      const recipient = tx.recipient || "Unknown";

      historyMessage += `📅 **Date:** ${date}\n`;
      historyMessage += `💰 **Amount:** ${amount} ${asset}\n`;
      historyMessage += `🔄 **Type:** ${type}\n`;
      historyMessage += `🎯 **Recipient:** ${recipient}\n`;
      historyMessage += `✅ **Status:** ${status}\n`;
      historyMessage += `---------------------\n`;
    });

    ctx.reply(historyMessage);
  } catch (error:any) {
    console.error("❌ Error fetching transaction history:", error.response?.data || error.message);
    ctx.reply("❌ Could not retrieve transaction history. Please try again later.");
  }
});

const PUSHER_KEY = process.env.PUSHER_KEY as string;
const PUSHER_CLUSTER = process.env.PUSHER_CLUSTER as string;


// 🔔 Function to initialize Pusher and listen for deposit notifications
async function initializePusher(chatId: number, token: string, organizationId: string) {
  try {
    const pusherClient = new Pusher(PUSHER_KEY, {
      cluster: PUSHER_CLUSTER,
      authorizer: (channel : any) => ({
        authorize: async (socketId : any, callback : any) => {
          try {
            const response = await axios.post(
              `${API_BASE}/api/notifications/auth`,
              { socket_id: socketId, channel_name: channel.name },
              { headers: { Authorization: `Bearer ${token}` } }
            );
      
            callback(null, response.data);
          } catch (error) {
            console.error("❌ Pusher authorization error:", error);
            callback(error, null);
          }
        },
      }),
      
    });

    // 📌 Subscribe to the private channel for deposit notifications
    const channel = pusherClient.subscribe(`private-org-${organizationId}`);

    channel.bind("pusher:subscription_succeeded", () => {
      console.log(`✅ Successfully subscribed to deposit notifications for chatId: ${chatId}`);
    });

    channel.bind("pusher:subscription_error", (error: any) => {
      console.error("❌ Subscription error:", error);
    });

    // 📌 Listen for deposit events
    channel.bind("deposit", (data: any) => {
      bot.telegram.sendMessage(
        chatId,
        `💰 **New Deposit Received!**\n\n✅ **Amount:** ${data.amount} ${data.asset}\n🌐 **Network:** ${data.network}`
      );
    });

    console.log(`🔔 Pusher initialized for chatId: ${chatId}`);
  } catch (error) {
    console.error("❌ Error initializing Pusher:", error);
  }
}

// 📌 Command: Enable notifications manually
bot.command("notifications", async (ctx) => {
  const chatId = ctx.chat.id;

  if (!userSessions[chatId] || !userSessions[chatId].token) {
    ctx.reply("⚠️ You are not logged in. Use `/login <email>` first.");
    return;
  }

  const { token } = userSessions[chatId];
  const organizationId = "YOUR_ORG_ID";  // 🚨 You should get this from API response

  ctx.reply("🔔 Enabling deposit notifications...");
  initializePusher(chatId, token, organizationId);
});

bot.command("help", (ctx) => {
  ctx.reply(
    `📖 **Available Commands:**\n\n` +
    `🔹 /start - Start the bot\n` +
    `🔹 /login <email> - Login with your email\n` +
    `🔹 /otp <code> - Enter OTP to authenticate\n` +
    `🔹 /balance - Check your wallet balance\n` +
    `🔹 /wallets - View your available wallets\n` +
    `🔹 /send <amount> <asset> <recipient> - Send funds\n` +
    `🔹 /confirm - Confirm pending transaction\n` +
    `🔹 /withdraw <amount> <asset> <bank_account_id> - Withdraw funds\n` +
    `🔹 /confirmwithdraw - Confirm withdrawal request\n` +
    `🔹 /history - View last 10 transactions\n` +
    `🔹 /notifications - Enable deposit notifications\n\n` +
    `🚀 Use these commands to manage your USDC transactions seamlessly!`
  );
});
















// Start the bot
bot.launch().then(() => {
  console.log("🤖 Copperx Payout Bot (English Version) started...");
});
