import { world } from "./world";
const list = (value: string) => value.split(/[\s,]+/).filter(Boolean);
function addressChoices(select: HTMLSelectElement) {
  const original = select.closest("label")!;
  const title = select.getAttribute("aria-label") || "Addresses";
  const field = document.createElement("fieldset");
  field.className = "policy-checkbox-picker";
  const legend = document.createElement("legend");
  legend.textContent = title;
  const search = document.createElement("input");
  search.type = "search";
  search.placeholder = "Find an object or group";
  search.setAttribute("aria-label", "Find " + title.toLowerCase());
  const rows = document.createElement("div");
  rows.className = "policy-picker-rows";
  const status = document.createElement("small");
  status.setAttribute("aria-live", "polite");
  const options = Array.from(select.options).map((option) => {
    const label = document.createElement("label");
    label.className = "check";
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = option.selected;
    const text = document.createElement("span");
    text.textContent = option.textContent;
    label.append(box, text);
    rows.append(label);
    box.addEventListener("change", () => {
      option.selected = box.checked;
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    return { option, box, label };
  });
  const update = () => {
    for (const item of options) item.box.checked = item.option.selected;
    status.textContent = options.length
      ? `${options.filter((item) => item.option.selected).length} selected`
      : "No address objects yet. Create them in Address objects.";
  };
  search.addEventListener("input", () => {
    for (const item of options)
      item.label.hidden = !item.option
        .textContent!.toLowerCase()
        .includes(search.value.trim().toLowerCase());
  });
  select.addEventListener("change", update);
  field.append(legend, search, rows, status);
  original.before(field);
  original.hidden = true;
  const help = original.nextElementSibling;
  if (help?.tagName === "SMALL")
    help.textContent =
      "Select any objects or groups. Their saved definitions are reused by this policy.";
  update();
}
function countryChoices(form: HTMLFormElement) {
  const input = form.elements.namedItem(
    "network_countries",
  ) as HTMLInputElement;
  const original = input.closest("label")!;
  const mode = form.elements.namedItem("network_geo_mode") as HTMLSelectElement;
  // ISO 3166-1 countries and territories, including places absent from map geometry.
  const countryCodes =
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(
      " ",
    );
  const names = new Map(
    world
      .filter((item) => /^[A-Z]{2}$/.test(item.code))
      .map((item) => [item.code, item.name]),
  );
  const regionNames = new Intl.DisplayNames(undefined, { type: "region" });
  const name = (code: string) => {
    try {
      return names.get(code) || regionNames.of(code) || code;
    } catch {
      return code;
    }
  };
  for (const code of countryCodes)
    if (!names.has(code)) names.set(code, name(code));
  const field = document.createElement("fieldset");
  field.className = "policy-country-picker";
  const legend = document.createElement("legend");
  legend.textContent = "Countries";
  const search = document.createElement("input");
  search.type = "search";
  search.placeholder = "Find a country by name or code";
  search.setAttribute("aria-label", "Find countries");
  const tags = document.createElement("div");
  tags.className = "policy-country-tags";
  tags.setAttribute("aria-label", "Selected countries");
  const rows = document.createElement("div");
  rows.className = "policy-picker-rows";
  const status = document.createElement("small");
  status.setAttribute("aria-live", "polite");
  const exact = document.createElement("details");
  exact.className = "advanced policy-picker-exact";
  const summary = document.createElement("summary");
  summary.textContent = "Enter country codes directly";
  exact.append(summary);
  const selected = () => new Set(list(input.value).map((v) => v.toUpperCase()));
  const write = (codes: Set<string>) => {
    input.value = [...codes].sort().join(", ");
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const update = () => {
    const active = document.activeElement as HTMLElement | null;
    const activeCode = active?.dataset.countryCode;
    const wasTag = !!active && tags.contains(active);
    const codes = selected();
    const bad = [...codes].some(
      (code) => !/^[A-Z]{2}$/.test(code) || ["XX", "ZZ"].includes(code),
    );
    input.setCustomValidity(
      bad
        ? "Use two-letter country codes; configure unknown locations separately."
        : "",
    );
    search.setCustomValidity(
      mode.value !== "off" && !codes.size
        ? "Select at least one country or turn Geo mode off."
        : "",
    );
    tags.replaceChildren();
    for (const code of codes) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "policy-country-chip";
      chip.textContent = `${name(code)} · ${code} ×`;
      chip.setAttribute("aria-label", "Remove country " + code);
      chip.addEventListener("click", () => {
        const next = selected();
        next.delete(code);
        write(next);
      });
      tags.append(chip);
    }
    rows.replaceChildren();
    const term = search.value.trim().toLowerCase();
    const choices = new Map(names);
    for (const code of codes) choices.set(code, name(code));
    for (const [code, text] of [...choices].sort((a, b) =>
      a[1].localeCompare(b[1]),
    )) {
      if (!`${code} ${text}`.toLowerCase().includes(term)) continue;
      const label = document.createElement("label");
      label.className = "check";
      const box = document.createElement("input");
      box.type = "checkbox";
      box.checked = codes.has(code);
      box.dataset.countryCode = code;
      const span = document.createElement("span");
      span.textContent = `${text} · ${code}`;
      label.append(box, span);
      rows.append(label);
      box.addEventListener("change", () => {
        const next = selected();
        if (box.checked) next.add(code);
        else next.delete(code);
        write(next);
      });
    }
    status.textContent = `${codes.size} selected · unknown locations are configured separately`;
    if (activeCode)
      Array.from(rows.querySelectorAll<HTMLInputElement>("[data-country-code]"))
        .find((box) => box.dataset.countryCode === activeCode)
        ?.focus({ preventScroll: true });
    else if (wasTag) search.focus({ preventScroll: true });
  };
  field.append(legend, search, tags, rows, status, exact);
  original.before(field);
  exact.append(original);
  input.addEventListener("input", update);
  input.addEventListener("change", update);
  mode.addEventListener("change", update);
  search.addEventListener("input", update);
  update();
}
export function mountPolicyPickers(form: HTMLFormElement) {
  for (const select of form.querySelectorAll<HTMLSelectElement>(
    "select[multiple]",
  ))
    addressChoices(select);
  countryChoices(form);
  return {
    enhanceGroup: (group: HTMLElement) => {
      const input = group.querySelector<HTMLInputElement>(
        "[data-group-methods]",
      )!;
      const label = input.closest("label")!;
      const field = document.createElement("fieldset");
      field.className = "policy-method-picker";
      const legend = document.createElement("legend");
      legend.textContent = "HTTP methods";
      field.append(legend);
      const verbs = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
      ];
      const buttons = document.createElement("div");
      buttons.className = "policy-method-chips";
      for (const verb of ["All methods", ...verbs]) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = verb;
        button.dataset.method = verb;
        button.addEventListener("click", () => {
          const current = list(input.value);
          input.value =
            verb === "All methods"
              ? ""
              : current.some((v) => v.toUpperCase() === verb)
                ? current.filter((v) => v.toUpperCase() !== verb).join(", ")
                : [...current, verb].join(", ");
          input.dispatchEvent(new Event("input", { bubbles: true }));
        });
        buttons.append(button);
      }
      const note = document.createElement("small");
      const exact = document.createElement("details");
      exact.className = "advanced";
      const summary = document.createElement("summary");
      summary.textContent = "Other methods / exact list";
      exact.append(summary);
      label.before(field);
      exact.append(label);
      field.append(buttons, note, exact);
      const update = () => {
        const selected = list(input.value).map((v) => v.toUpperCase());
        for (const button of buttons.querySelectorAll("button"))
          button.setAttribute(
            "aria-pressed",
            String(
              button.dataset.method === "All methods"
                ? !selected.length
                : selected.includes(button.dataset.method!),
            ),
          );
        note.textContent = selected.length
          ? "Matches: " + selected.join(", ")
          : "No method restriction. The group's path and rule conditions still apply.";
      };
      input.addEventListener("input", update);
      input.addEventListener("change", update);
      update();
    },
  };
}
