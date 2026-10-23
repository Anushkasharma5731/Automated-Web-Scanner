"use strict";
document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector('form[action$="/scan"]');
  if (!form) return;
  form.addEventListener("submit", () => {
    const button = form.querySelector('button[type="submit"]');
    const loading = document.getElementById("loading");
    if (button) button.disabled = true;
    if (loading) loading.hidden = false;
  });
});
