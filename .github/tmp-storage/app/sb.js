import { createClient } from "@supabase/supabase-js";
const supabase = createClient("http://127.0.0.1:54321", "ANONKEY");
export async function up(file, id) {
  await supabase.storage.from("files").upload(`uploads/${id}/${file.name}`, file);
  const bucket = supabase.storage.from("avatars");
  await bucket.upload("public/" + id + ".png", file, { upsert: true });
  const { data } = await supabase.from("profiles").select("*");
  return data;
}
window.up = up;
