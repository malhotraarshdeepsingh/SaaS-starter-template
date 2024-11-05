import { Webhook } from "svix";
import { headers } from "next/headers";
import { WebhookEvent } from "@clerk/nextjs/server";
import prisma from "@/lib/prisma";

export async function POST(req: Request){
    const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
    if(!WEBHOOK_SECRET) {
        throw new Error("Missing WEBHOOK_SECRET environment variable");
    }

    const headerPayload = headers()
    const svix_id = headerPayload.get("svix-id")
    const svix_timestamp = headerPayload.get("svix-timestamp")
    const svix_signature = headerPayload.get("svix-signature")

    if(!svix_id || !svix_timestamp || !svix_signature){
        return new Response("Error occurred: No SVIX HEADERS found")
    }

    const payload = await req.json()
    const body = JSON.stringify(payload)

    const wh = new Webhook(WEBHOOK_SECRET);

    let evt: WebhookEvent;

    try {
        evt = wh.verify(body, {
            "svix-id": svix_id,
            "svix-timestamp": svix_timestamp,
            "svix-signature": svix_signature
        }) as WebhookEvent;
        // log
    } catch (error) {
        console.error("Error while verifying webhook",error)
        return new Response("Error occurred: Failed to verify webhook", {status: 404})
    }

    const {id} = evt.data;
    const eventType = evt.type;

    if(eventType === "user.created") {
        try {
            const { email_addresses , primary_email_address_id } = evt.data;
            // log
            console.log("New user created: ", evt.data);

            const primaryEmail = email_addresses.find(
                ( email ) => email.id === primary_email_address_id
            )

            if(!primaryEmail) {
                return new Response("No primary email found", { status: 400 });
            }

            const newUser = await prisma.user.create({
                data: {
                    id: evt.data.id!,
                    email: primaryEmail.email_address,
                    isSubscribed: false,
                }
            })

            if(newUser){
                console.log("User created in the database: ", newUser);
                return new Response("User created successfully", { status: 200 });
            }
        } catch (error) {
            return new Response("Error creating user",{ status: 400})
        }
    }

    return new Response("Webhook recieved Successfully", { status: 200 });
}