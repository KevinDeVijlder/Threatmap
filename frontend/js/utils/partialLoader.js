/**
 * Modular HTML Partial Loader
 * ===========================
 * Fetches HTML partial templates referenced by `[data-partial]` placeholders
 * and injects them in-place so the DOM matches the full dashboard layout.
 */

export async function loadHtmlPartials() {
  const placeholders = Array.from(document.querySelectorAll("[data-partial]"));
  await Promise.all(
    placeholders.map(async (el) => {
      const path = el.getAttribute("data-partial");
      const response = await fetch(path);
      if (!response.ok) {
        throw new Error(`Failed to load HTML partial: ${path}`);
      }
      const html = await response.text();
      el.outerHTML = html;
    })
  );
}
