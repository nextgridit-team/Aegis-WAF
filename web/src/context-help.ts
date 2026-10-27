import topics from "./help-topics.json";
const selector = "label.field,label.check,h2,h3,h4,summary,th,legend";
// Match authored control captions only: never rewrite traffic samples, values or logs.
const byLabel = new Map(
  topics.flatMap((topic) =>
    topic.labels.map((label) => [label.toLowerCase(), topic] as const),
  ),
);
export function installContextHelp(root: HTMLElement) {
  let trigger: HTMLButtonElement | null = null;
  const popover = document.createElement("section");
  popover.id = "context-help";
  popover.className = "context-help-popover";
  popover.setAttribute("popover", "auto");
  popover.setAttribute("role", "dialog");
  popover.setAttribute("aria-modal", "false");
  popover.setAttribute("aria-labelledby", "context-help-title");
  const title = document.createElement("h2");
  title.id = "context-help-title";
  const description = document.createElement("p");
  description.id = "context-help-description";
  popover.setAttribute("aria-describedby", description.id);
  const link = document.createElement("a");
  link.textContent = "Read detailed explanation";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  const linkNote = document.createElement("small");
  linkNote.textContent = "Opens the built-in guide in a new tab.";
  const close = document.createElement("button");
  close.type = "button";
  close.className = "context-help-close";
  close.textContent = "Close";
  popover.append(title, description, link, linkNote, close);
  const dismiss = () => {
    if (popover.matches(":popover-open")) popover.hidePopover();
    trigger?.setAttribute("aria-expanded", "false");
  };
  close.addEventListener("click", () => {
    dismiss();
    trigger?.focus({ preventScroll: true });
  });
  popover.addEventListener("toggle", () => {
    const open = popover.matches(":popover-open");
    trigger?.setAttribute("aria-expanded", String(open));
  });
  const position = () => {
    if (!trigger || !popover.matches(":popover-open")) return;
    const width = innerWidth,
      height = innerHeight;
    popover.style.maxWidth = width - 32 + "px";
    popover.style.maxHeight = height - 32 + "px";
    if (width < 540) {
      Object.assign(popover.style, {
        left: "auto",
        top: "auto",
        right: 16 + "px",
        bottom: 16 + "px",
      });
      return;
    }
    const rect = trigger.getBoundingClientRect(),
      box = popover.getBoundingClientRect();
    const boxWidth = box.width,
      boxHeight = box.height;
    const left = Math.max(
      16,
      Math.min(width - boxWidth - 16, rect.right - boxWidth),
    );
    const below = rect.bottom + 8;
    const top = Math.max(
      16,
      Math.min(
        height - boxHeight - 16,
        below + boxHeight <= height - 16 ? below : rect.top - 8 - boxHeight,
      ),
    );
    Object.assign(popover.style, {
      left: left + "px",
      top: top + "px",
      right: "auto",
      bottom: "auto",
    });
  };
  window.addEventListener("resize", position);
  document.addEventListener("scroll", position, {
    capture: true,
    passive: true,
  });
  const open = (button: HTMLButtonElement, topic: (typeof topics)[number]) => {
    if (trigger === button && popover.matches(":popover-open")) {
      dismiss();
      return;
    }
    dismiss();
    trigger?.setAttribute("aria-expanded", "false");
    trigger = button;
    title.textContent = topic.title;
    description.textContent = topic.summary;
    link.href = `/help.html#${topic.id}`;
    // A popover opened from a modal must be inside that modal to escape its inert boundary.
    (button.closest("dialog") || document.body).append(popover);
    popover.showPopover();
    position();
    button.setAttribute("aria-expanded", "true");
    close.focus({ preventScroll: true });
  };
  const caption = (element: Element) => {
    if (
      element.tagName === "SUMMARY" &&
      element.firstElementChild?.tagName === "SPAN"
    )
      return element.firstElementChild.textContent?.trim() || "";
    if (element.matches("label.check"))
      return element.querySelector("span")?.textContent?.trim() || "";
    const direct = [...element.childNodes]
      .filter((n) => n.nodeType === Node.TEXT_NODE)
      .map((n) => n.textContent)
      .join("")
      .trim();
    return (
      direct ||
      (element.matches("label")
        ? element.getAttribute("aria-label") || ""
        : element.textContent?.trim() || "")
    );
  };
  const annotate = (element: Element) => {
    if (
      element.hasAttribute("data-context-help-ready") ||
      element.closest(".context-help-popover") ||
      element.closest("[data-context-help-ignore]")
    )
      return;
    const topic = byLabel.get(caption(element).toLowerCase());
    if (!topic) return;
    // The browser and editor code keep their original labels, controls and values.
    element.setAttribute("data-context-help-ready", "");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.helpTopic = topic.id;
    button.className = "context-help-trigger";
    button.textContent = "?";
    button.setAttribute("aria-label", `Explain ${topic.title}`);
    button.setAttribute("aria-controls", popover.id);
    button.setAttribute("aria-expanded", "false");
    button.setAttribute("aria-haspopup", "dialog");
    let pointerOpened = false;
    button.addEventListener("pointerdown", () => {
      pointerOpened = trigger === button && popover.matches(":popover-open");
    });
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      // Native light-dismiss can run before click when the same trigger is pressed.
      const toggleClosed = event.detail > 0 && pointerOpened;
      pointerOpened = false;
      if (toggleClosed) dismiss();
      else open(button, topic);
    });
    if (element.tagName === "TH") {
      element.setAttribute("aria-label", caption(element));
      button.classList.add("context-help-inline");
      element.append(button);
    } else if (element.tagName === "LEGEND") {
      // Legend placement must remain the first child of its fieldset.
      const host = element.parentElement!;
      host.classList.add("context-help-legend-host");
      host.append(button);
    } else {
      const target =
        element.tagName === "SUMMARY" ? element.parentElement! : element;
      const host = document.createElement("div");
      host.className =
        element.tagName === "SUMMARY"
          ? "context-help-disclosure-host"
          : element.matches("label")
            ? "context-help-field-host"
            : "context-help-heading-host";
      if (element.matches("label.check"))
        host.classList.add("context-help-check-host");
      target.before(host);
      host.append(target, button);
      if (element.matches("label.field")) {
        const first = element.firstChild;
        if (first?.nodeType === Node.TEXT_NODE) {
          const text = document.createElement("span");
          text.className = "context-help-caption";
          first.before(text);
          text.append(first);
        }
      }
    }
  };
  const scan = (element: Element) => {
    if (element.matches(selector)) annotate(element);
    element.querySelectorAll(selector).forEach(annotate);
  };
  const observer = new MutationObserver((records) => {
    if (trigger && !trigger.isConnected) {
      dismiss();
      trigger = null;
    }
    const added = new Set<Element>();
    for (const record of records)
      for (const node of record.addedNodes)
        if (node instanceof Element && !node.closest(".context-help-popover"))
          added.add(node);
    for (const node of added) if (node.isConnected) scan(node);
  });
  scan(root);
  observer.observe(root, { childList: true, subtree: true });
  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key === "Escape" && popover.matches(":popover-open")) {
        event.preventDefault();
        event.stopPropagation();
        dismiss();
        trigger?.focus({ preventScroll: true });
      }
    },
    true,
  );
  // Closing the parent editor also dismisses help, without reopening or changing it.
  root.addEventListener(
    "close",
    (event) => {
      if (
        event.target instanceof HTMLDialogElement &&
        event.target.contains(popover)
      )
        dismiss();
    },
    true,
  );
}
