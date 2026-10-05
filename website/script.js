const menuButton = document.querySelector(".menu-toggle");
const navigation = document.querySelector(".primary-nav");

if (menuButton && navigation) {
  menuButton.addEventListener("click", () => {
    const expanded = menuButton.getAttribute("aria-expanded") === "true";
    menuButton.setAttribute("aria-expanded", String(!expanded));
    menuButton.setAttribute("aria-label", expanded ? "Menü öffnen" : "Menü schließen");
    navigation.classList.toggle("is-open", !expanded);
  });

  navigation.addEventListener("click", event => {
    if (event.target.closest("a")) {
      menuButton.setAttribute("aria-expanded", "false");
      menuButton.setAttribute("aria-label", "Menü öffnen");
      navigation.classList.remove("is-open");
    }
  });
}

const tabs = [...document.querySelectorAll(".demo-tab")];

for (const tab of tabs) {
  tab.addEventListener("click", () => {
    const activePanel = tab.dataset.panel;
    for (const candidate of tabs) {
      const selected = candidate === tab;
      candidate.classList.toggle("is-selected", selected);
      candidate.setAttribute("aria-selected", String(selected));
      candidate.tabIndex = selected ? 0 : -1;
    }
    for (const panel of document.querySelectorAll(".demo-panel")) {
      panel.hidden = panel.id !== `panel-${activePanel}`;
    }
  });
}

for (const button of document.querySelectorAll(".copy-button")) {
  button.addEventListener("click", async () => {
    const message = document.querySelector(".copy-status");
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      message.textContent = "Befehl in die Zwischenablage kopiert.";
    } catch {
      message.textContent = "Kopieren nicht verfügbar. Befehl bitte markieren und kopieren.";
    }
  });
}
