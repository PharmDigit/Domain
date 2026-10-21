const { onRequest } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const {
  getFirestore,
  FieldValue,
  Timestamp,
} = require("firebase-admin/firestore");
const Stripe = require("stripe");

initializeApp();

const db = getFirestore();

const STRIPE_SECRET_KEY = defineSecret("STRIPE_SECRET_KEY");
const STRIPE_WEBHOOK_SECRET = defineSecret("STRIPE_WEBHOOK_SECRET");

// Every price the server will sell. "app" decides which pass it unlocks and where the buyer returns.
//   qbank     -> Firestore entitlements/{uid}            (PharmDosage Q-Bank, unchanged)
//   pharmcalc -> Firestore pharmcalc_entitlements/{uid}  (PharmCalculation)
//   pharmpk   -> Firestore pharmpk_entitlements/{uid}    (PharmPK)
//   pharmrx   -> Firestore pharmrx_entitlements/{uid}    (PharmRx)
//   pharmtherapy -> Firestore pharmtherapy_entitlements/{uid} (PharmTherapy)
const PRICES = {
  // PharmDosage Q-Bank (unchanged)
  "price_1UO8biRpvhB9DoxSXlzJDynA": { app: "qbank", planType: "semester" },
  "price_1UO8c7RpvhB9DoxSkXL2gKFP": { app: "qbank", planType: "lifetime" },
  // PharmCalculation
  "price_1UQD4fRpvhB9DoxSCImf37ZJ": { app: "pharmcalc", planType: "semester" },
  "price_1UQD50RpvhB9DoxSub7bPaWY": { app: "pharmcalc", planType: "lifetime" },
  // PharmPK
  "price_1UQD5NRpvhB9DoxStncvt7Bd": { app: "pharmpk", planType: "semester" },
  "price_1UQD5fRpvhB9DoxStv3S00pY": { app: "pharmpk", planType: "lifetime" },
  // PharmRx
  "price_1URIjQRpvhB9DoxSnUD9gyFK": { app: "pharmrx", planType: "semester" },
  "price_1URIkzRpvhB9DoxSx5dFGyK4": { app: "pharmrx", planType: "lifetime" },
  // PharmTherapy
  "price_1USnWTRpvhB9DoxS6JilWji8": { app: "pharmtherapy", planType: "semester" },
  "price_1USnX3RpvhB9DoxSv49L4tEH": { app: "pharmtherapy", planType: "lifetime" },
};

const APPS = {
  qbank: {
    collection: "entitlements",
    successUrl:
      "https://www.pharmdigit.com/?payment=success&session_id={CHECKOUT_SESSION_ID}",
    cancelUrl: "https://www.pharmdigit.com/?payment=cancelled",
  },
  pharmcalc: {
    collection: "pharmcalc_entitlements",
    successUrl: "https://www.pharmdigit.com/pharmcalculation/#/plans/paid",
    cancelUrl: "https://www.pharmdigit.com/pharmcalculation/#/plans",
  },
  pharmpk: {
    collection: "pharmpk_entitlements",
    successUrl:
      "https://www.pharmdigit.com/pharmpk/?pk_checkout=success&session_id={CHECKOUT_SESSION_ID}",
    cancelUrl: "https://www.pharmdigit.com/pharmpk/?pk_checkout=cancel",
  },
  pharmrx: {
    collection: "pharmrx_entitlements",
    successUrl:
      "https://www.pharmdigit.com/pharmrx/?rx_checkout=success&session_id={CHECKOUT_SESSION_ID}",
    cancelUrl: "https://www.pharmdigit.com/pharmrx/?rx_checkout=cancel",
  },
  pharmtherapy: {
    collection: "pharmtherapy_entitlements",
    successUrl:
      "https://www.pharmdigit.com/pharmtherapy/?pt_checkout=success&session_id={CHECKOUT_SESSION_ID}",
    cancelUrl: "https://www.pharmdigit.com/pharmtherapy/?pt_checkout=cancel",
  },
};

const ALLOWED_ORIGINS = [
  "https://www.pharmdigit.com",
  "https://pharmdigit.com",
];

function addCalendarMonths(date, months) {
  const result = new Date(date);
  const day = result.getDate();

  result.setDate(1);
  result.setMonth(result.getMonth() + months);

  const lastDay = new Date(
    result.getFullYear(),
    result.getMonth() + 1,
    0
  ).getDate();

  result.setDate(Math.min(day, lastDay));
  return result;
}

// Create a Stripe Checkout session for a logged-in Firebase user.
exports.createCheckoutSession = onRequest(
  {
    cors: ALLOWED_ORIGINS,
    secrets: [STRIPE_SECRET_KEY],
    maxInstances: 5,
  },
  async (req, res) => {
    if (req.method !== "POST") {
      return res.status(405).json({ error: "POST required." });
    }

    try {
      const authorization = req.get("Authorization") || "";
      const match = authorization.match(/^Bearer (.+)$/i);

      if (!match) {
        return res.status(401).json({
          error: "Please sign in before purchasing.",
        });
      }

      const decoded = await getAuth().verifyIdToken(match[1]);
      const priceId = req.body && req.body.priceId;
      const product = PRICES[priceId];

      if (!product) {
        return res.status(400).json({
          error: "Invalid product price.",
        });
      }

      const stripe = new Stripe(STRIPE_SECRET_KEY.value());

      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        line_items: [{ price: priceId, quantity: 1 }],
        automatic_tax: { enabled: true },
        client_reference_id: decoded.uid,
        metadata: {
          firebaseUID: decoded.uid,
          planType: product.planType,
          priceId,
          app: product.app,
        },
        success_url: APPS[product.app].successUrl,
        cancel_url: APPS[product.app].cancelUrl,
      });

      return res.status(200).json({ url: session.url });
    } catch (error) {
      console.error("Checkout creation failed:", error.message);
      return res.status(500).json({
        error: "Unable to start checkout. Please try again.",
      });
    }
  }
);

// Grant access only after Stripe sends a verified payment webhook.
exports.stripeWebhook = onRequest(
  {
    secrets: [STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET],
    maxInstances: 5,
  },
  async (req, res) => {
    if (req.method !== "POST") {
      return res.status(405).send("POST required.");
    }

    const signature = req.get("stripe-signature");

    if (!signature) {
      return res.status(400).send("Missing Stripe signature.");
    }

    let event;

    try {
      const stripe = new Stripe(STRIPE_SECRET_KEY.value());

      event = stripe.webhooks.constructEvent(
        req.rawBody,
        signature,
        STRIPE_WEBHOOK_SECRET.value()
      );
    } catch (error) {
      console.error("Stripe signature verification failed.");
      return res.status(400).send("Invalid webhook signature.");
    }

    try {
      if (
        event.type !== "checkout.session.completed" &&
        event.type !== "checkout.session.async_payment_succeeded"
      ) {
        return res.status(200).send("Event received.");
      }

      const session = event.data.object;

      if (session.payment_status !== "paid") {
        return res.status(200).send("Payment not completed.");
      }

      const uid = session.metadata && session.metadata.firebaseUID;
      const priceId = session.metadata && session.metadata.priceId;
      const product = PRICES[priceId];

      // Checkouts this server did not create (no known price) are acknowledged and
      // ignored. Answering 400 would make Stripe retry them for days.
      if (!product) {
        return res.status(200).send("Ignored: not a PharmDigit price.");
      }

      const planType = product.planType;

      if (!uid || !planType || session.metadata.planType !== planType) {
        return res.status(400).send("Invalid purchase metadata.");
      }

      const eventRef = db.collection("stripeWebhookEvents").doc(event.id);
      // The price (not client data) decides which app is unlocked.
      const entitlementRef = db
        .collection(APPS[product.app].collection)
        .doc(uid);

      await db.runTransaction(async (transaction) => {
        const eventDoc = await transaction.get(eventRef);

        if (eventDoc.exists) {
          return;
        }

        const entitlementDoc = await transaction.get(entitlementRef);
        const existing = entitlementDoc.exists
          ? entitlementDoc.data()
          : {};

        // Never downgrade lifetime access.
        if (existing.planType !== "lifetime") {
          if (planType === "lifetime") {
            transaction.set(
              entitlementRef,
              {
                planType: "lifetime",
                expiresAt: null,
                updatedAt: FieldValue.serverTimestamp(),
              },
              { merge: true }
            );
          } else {
            const now = new Date();
            const currentExpiry =
              existing.expiresAt &&
              typeof existing.expiresAt.toDate === "function"
                ? existing.expiresAt.toDate()
                : null;

            const baseDate =
              currentExpiry && currentExpiry > now
                ? currentExpiry
                : now;

            const expiresAt = addCalendarMonths(baseDate, 6);

            transaction.set(
              entitlementRef,
              {
                planType: "semester",
                expiresAt: Timestamp.fromDate(expiresAt),
                updatedAt: FieldValue.serverTimestamp(),
              },
              { merge: true }
            );
          }
        }

        transaction.set(eventRef, {
          processedAt: FieldValue.serverTimestamp(),
        });
      });

      return res.status(200).send("Payment processed.");
    } catch (error) {
      console.error("Webhook processing failed:", error.message);
      return res.status(500).send("Webhook processing failed.");
    }
  }
);

// ---------------------------------------------------------------------------
// Beta codes
// Firestore: beta_codes/{CODE}
//   active: true|false              switch a code on or off
//   appIds: ["qbank","pharmCalculation","PharmPK","PharmTherapy","PharmRx"]   apps it unlocks
//   durationDays: 60                 length of beta access from the day it is redeemed
//   redeemedCount: 0                 updated by this function
//   maxRedemptions: 50  (optional)   total accounts that may redeem it
//   redeemBy: <timestamp> (optional) last moment the code can be redeemed
// Each account can redeem a code once: beta_codes/{CODE}/redemptions/{uid}.
// Grants { planType: "beta", expiresAt } in each app's entitlement collection,
// except where the account already has an active paid pass (left unchanged).
// ---------------------------------------------------------------------------
const APP_ALIASES = {
  qbank: "qbank", pharmdosage: "qbank", dosage: "qbank",
  pharmcalculation: "pharmcalc", pharmcalc: "pharmcalc",
  pharmpk: "pharmpk",
  pharmrx: "pharmrx",
  pharmtherapy: "pharmtherapy", pharmacotherapy: "pharmtherapy",
};

class BetaError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function toDate(v) {
  return v && typeof v.toDate === "function" ? v.toDate() : null;
}

exports.redeemBetaCode = onRequest(
  {
    cors: ALLOWED_ORIGINS,
    maxInstances: 5,
  },
  async (req, res) => {
    if (req.method !== "POST") {
      return res.status(405).json({ error: "POST required." });
    }

    try {
      const authorization = req.get("Authorization") || "";
      const match = authorization.match(/^Bearer (.+)$/i);
      if (!match) {
        return res.status(401).json({ error: "Please sign in to redeem a beta code." });
      }
      const decoded = await getAuth().verifyIdToken(match[1]);
      const uid = decoded.uid;

      const code = String((req.body && req.body.code) || "")
        .trim()
        .toUpperCase();
      if (!/^[A-Z0-9_-]{3,40}$/.test(code)) {
        return res.status(400).json({ error: "Enter a valid beta code." });
      }

      const codeRef = db.collection("beta_codes").doc(code);
      const redemptionRef = codeRef.collection("redemptions").doc(uid);

      const result = await db.runTransaction(async (tx) => {
        const codeDoc = await tx.get(codeRef);
        if (!codeDoc.exists || codeDoc.data().active !== true) {
          throw new BetaError(404, "This beta code is not valid.");
        }
        const c = codeDoc.data();
        const now = new Date();

        const redeemBy = toDate(c.redeemBy);
        if (redeemBy && redeemBy < now) {
          throw new BetaError(410, "This beta code has expired.");
        }
        const used = Number(c.redeemedCount) || 0;
        if (typeof c.maxRedemptions === "number" && used >= c.maxRedemptions) {
          throw new BetaError(410, "This beta code has reached its limit.");
        }

        const already = await tx.get(redemptionRef);
        if (already.exists) {
          const prev = toDate(already.data().expiresAt);
          throw new BetaError(
            409,
            "You have already redeemed this code" +
              (prev ? ". Your beta access runs until " + prev.toISOString().slice(0, 10) + "." : ".")
          );
        }

        const apps = Array.from(
          new Set(
            (Array.isArray(c.appIds) ? c.appIds : [])
              .map((a) => APP_ALIASES[String(a).toLowerCase().replace(/[^a-z]/g, "")])
              .filter(Boolean)
          )
        );
        if (!apps.length) {
          throw new BetaError(500, "This beta code is not set up correctly. Please contact support@pharmdigit.com.");
        }

        const days = Math.min(Math.max(Number(c.durationDays) || 60, 1), 366);
        const expiresAt = new Date(now.getTime() + days * 86400000);

        // Read every entitlement before writing anything (transaction rule).
        const refs = apps.map((a) => db.collection(APPS[a].collection).doc(uid));
        const docs = [];
        for (const r of refs) docs.push(await tx.get(r));

        const granted = [];
        const kept = [];
        docs.forEach((d, i) => {
          const e = d.exists ? d.data() : {};
          const exp = toDate(e.expiresAt);
          const paidActive =
            e.planType === "lifetime" ||
            (e.planType === "semester" && exp && exp > now);
          const longerBeta = e.planType === "beta" && exp && exp >= expiresAt;
          if (paidActive || longerBeta) {
            kept.push(apps[i]);
            return;
          }
          tx.set(
            refs[i],
            {
              planType: "beta",
              expiresAt: Timestamp.fromDate(expiresAt),
              betaCode: code,
              updatedAt: FieldValue.serverTimestamp(),
            },
            { merge: true }
          );
          granted.push(apps[i]);
        });

        tx.set(redemptionRef, {
          uid,
          email: decoded.email || null,
          redeemedAt: FieldValue.serverTimestamp(),
          expiresAt: Timestamp.fromDate(expiresAt),
          granted,
          kept,
        });
        tx.update(codeRef, {
          redeemedCount: FieldValue.increment(1),
          lastRedeemedAt: FieldValue.serverTimestamp(),
        });

        return { expiresAt: expiresAt.getTime(), days, granted, kept };
      });

      return res.status(200).json({ ok: true, ...result });
    } catch (error) {
      if (error instanceof BetaError) {
        return res.status(error.status).json({ error: error.message });
      }
      console.error("Beta code redemption failed:", error.message);
      return res.status(500).json({ error: "Unable to redeem the code right now. Please try again." });
    }
  }
);
