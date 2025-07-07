import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cors from "cors";
import crypto from "crypto";
import serverless from "serverless-http";

dotenv.config();

const app = express();

app.use(express.json());
if (!process.env.CLIENT_URL) {
  throw new Error("CLIENT_URL is not defined");
}

if (!process.env.SECRET_KEY) {
  throw new Error("SECRET_KEY is not defined");
}

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: ["POST", "GET"],
  })
);

mongoose
  .connect(process.env.DB_URL!)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

function generateKey(textId: string): Buffer {
  const combinedKey = textId + process.env.SECRET_KEY;
  return crypto.createHash('sha256').update(combinedKey).digest();
}

function encrypt(text: string, textId: string): string {
  if (!text) return '';
  
  const key = generateKey(textId);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText: string, textId: string): string {
  if (!encryptedText) return '';
  
  try {
    const key = generateKey(textId);
    const textParts = encryptedText.split(':');
    
    if (textParts.length !== 2) {
      throw new Error('Invalid encrypted text format');
    }
    
    const iv = Buffer.from(textParts[0]!, 'hex');
    const encrypted = textParts[1];
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(encrypted!, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt data');
  }
}

const textDocumentSchema = new mongoose.Schema(
  {
    textId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    data: {
      type: String,
      required: true,
      default: "",
    },
  },
  {
    timestamps: true,
  }
);

const TextDocument = mongoose.model("TextDocument", textDocumentSchema);

app.post("/api/documents", async (req, res): Promise<void> => {
  try {
    const { textId, data } = req.body;

    if (!textId) {
      res.status(400).json({
        error: "textId is required",
      });
      return;
    }

    if (data === undefined || data === null) {
      res.status(400).json({
        error: "data field is required",
      });
      return;
    }

    const encryptedData = encrypt(data, textId);

    const document = await TextDocument.findOneAndUpdate(
      { textId },
      { data: encryptedData },
      {
        new: true,
        upsert: true,
        runValidators: true,
      }
    );

    const decryptedData = decrypt(document.data, textId);

    res.status(200).json({
      success: true,
      message: "Document saved successfully",
      document: {
        textId: document.textId,
        data: decryptedData,
        createdAt: document.createdAt,
        updatedAt: document.updatedAt,
      },
    });
  } catch (error) {
    console.error("Error saving document:", error);
    res.status(500).json({
      error: "Internal server error",
      message: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.get("/api/documents/:textId", async (req, res): Promise<void> => {
  try {
    const { textId } = req.params;

    const document = await TextDocument.findOne({ textId });

    if (!document) {
      res.status(404).json({
        error: "Document not found",
      });
      return;
    }

    const decryptedData = decrypt(document.data, textId);

    res.status(200).json({
      success: true,
      document: {
        textId: document.textId,
        data: decryptedData,
        createdAt: document.createdAt,
        updatedAt: document.updatedAt,
      },
    });

    return;
  } catch (error) {
    console.error("Error retrieving document:", error);
    res.status(500).json({
      error: "Internal server error",
      message: error instanceof Error ? error.message : "Unknown error",
    });
    return;
  }
});

app.get("/", (req, res) => {
  res.send("Server is running!!");
});

export const handler = serverless(app);