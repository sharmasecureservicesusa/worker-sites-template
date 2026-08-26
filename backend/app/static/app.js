document.addEventListener("submit", (event) => {
    const button = event.target.querySelector("button[type=submit]");
    if (button && !button.disabled) {
        button.dataset.label = button.textContent;
        button.textContent = "Working…";
        button.disabled = true;
    }
});
