import { initializeApp } from "firebase/app";
import { getStorage, ref, uploadBytes, getDownloadURL, connectStorageEmulator } from "firebase/storage";
const app = initializeApp({ apiKey: "AIzaSyDemoDemoDemoDemoDemoDemoDemo12345", authDomain: "demo-siegekit.firebaseapp.com", projectId: "demo-siegekit", storageBucket: "demo-siegekit.appspot.com", appId: "1:123:web:abc" });
const storage = getStorage(app);
if (location.hostname === "localhost") connectStorageEmulator(storage, "127.0.0.1", 9199);
export async function upload(file, uid) {
  const r = ref(storage, `uploads/${uid}/${file.name}`);
  await uploadBytes(r, file);
  const a = ref(storage, "avatars/" + uid + ".png");
  await uploadBytes(a, file);
  return getDownloadURL(r);
}
window.upload = upload;
