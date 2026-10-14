/*
 * Optional Firebase Web SDK configuration.
 * Add your public Firebase web-app config and deployed Cloud Functions region.
 * Never put a Firebase service-account key or another server secret here.
 */
window.OFFLINERUPEE_FIREBASE_CONFIG = {
  apiKey: "AIzaSyBfelITTIMApvMEqkN0eNcuB3kx8A2rPlM",
  authDomain: "offline-rupee.firebaseapp.com",
  projectId: "offline-rupee",
  appId: "1:640745077444:web:0aea6349fcf9cf48fea791",
  region: "asia-south1",
  // URL of the self-hosted API in server/ (e.g. https://offlinerupee-api.onrender.com).
  // When set, it replaces the Cloud Functions, so the project can stay on the Spark plan.
  apiBaseUrl: "https://offlinerupee-api.onrender.com",
};
