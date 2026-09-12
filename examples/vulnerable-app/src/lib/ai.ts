import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

export async function handleSupportMessage(req: any) {
  const userMessage = req.body.message;

  // Untrusted text placed in the system position, on a call that also has tools.
  const response = await client.messages.create({
    model: "claude-sonnet-5",
    max_tokens: 1024,
    system: `You are a helpful support agent. The customer said: ${userMessage}`,
    tools: [{ name: "issue_refund", description: "Refund an order", input_schema: {} }],
    messages: [{ role: "user", content: "Help the customer." }],
  });

  return response;
}
