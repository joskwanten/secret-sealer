// @ts-check

let nextId = 0;

const CHEVRON = '<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M3 4.5 6 7.5 9 4.5" /></svg>';

/**
 * Text field with a filterable option list (WAI-ARIA combobox pattern).
 * Free text is allowed: the options are suggestions, not a restriction.
 */
export class Combobox {
  /** @type {string[]} */
  #options = [];
  #loading = false;
  #disabled = false;
  #open = false;
  #activeIndex = -1;
  #listId = `combobox-list-${nextId++}`;
  /** @type {(value: string) => void} */
  #onChange;

  /**
   * @param {HTMLElement} host Element to render into.
   * @param {{ inputId: string, onChange: (value: string) => void }} options
   */
  constructor(host, { inputId, onChange }) {
    this.#onChange = onChange;

    this.root = document.createElement('div');
    this.root.className = 'combobox';

    this.input = document.createElement('input');
    Object.assign(this.input, { type: 'text', id: inputId, autocomplete: 'off', spellcheck: false });
    this.input.setAttribute('role', 'combobox');
    this.input.setAttribute('aria-autocomplete', 'list');
    this.input.setAttribute('aria-controls', this.#listId);
    this.input.setAttribute('aria-expanded', 'false');

    this.toggleButton = document.createElement('button');
    Object.assign(this.toggleButton, { type: 'button', className: 'combobox-toggle', tabIndex: -1 });
    this.toggleButton.setAttribute('aria-label', 'Toon namespaces');
    this.toggleButton.innerHTML = CHEVRON;

    this.list = document.createElement('ul');
    this.list.className = 'combobox-list';
    this.list.id = this.#listId;
    this.list.setAttribute('role', 'listbox');
    this.list.hidden = true;

    this.root.append(this.input, this.toggleButton, this.list);
    host.replaceWith(this.root);

    this.input.addEventListener('input', () => {
      this.#onChange(this.input.value);
      this.#show();
      this.#activeIndex = -1;
      this.#render();
    });
    this.input.addEventListener('click', () => this.#show());
    this.input.addEventListener('blur', () => this.#hide());
    this.input.addEventListener('keydown', (e) => this.#onKeydown(e));
    this.toggleButton.addEventListener('mousedown', (e) => e.preventDefault());
    this.toggleButton.addEventListener('click', () => {
      if (this.#open) {
        this.#hide();
      } else {
        this.input.focus();
        this.#show();
      }
    });
    // Keep focus in the field while clicking an option.
    this.list.addEventListener('mousedown', (e) => e.preventDefault());

    this.#render();
  }

  get value() {
    return this.input.value;
  }

  /** @param {string} value */
  set value(value) {
    if (this.input.value !== value) this.input.value = value;
  }

  /**
   * @param {{ options: string[], loading: boolean, disabled: boolean, placeholder: string }} props
   */
  update({ options, loading, disabled, placeholder }) {
    const changed =
      loading !== this.#loading ||
      disabled !== this.#disabled ||
      options.length !== this.#options.length ||
      options.some((o, i) => o !== this.#options[i]);
    this.input.placeholder = placeholder;
    if (!changed) return;

    this.#options = options;
    this.#loading = loading;
    this.#disabled = disabled;
    if (disabled) this.#open = false;
    this.#render();
  }

  /** All options while the value is empty or already one of them; otherwise the matches. */
  #filtered() {
    const query = this.value.trim().toLowerCase();
    if (!query || this.#options.includes(this.value.trim())) return this.#options;
    return this.#options.filter((o) => o.toLowerCase().includes(query));
  }

  /** @param {number} index */
  #optionId(index) {
    return `${this.#listId}-${index}`;
  }

  #show() {
    if (this.#disabled || (this.#options.length === 0 && !this.#loading)) return;
    this.#open = true;
    this.#activeIndex = this.#filtered().indexOf(this.value.trim());
    this.#render();
  }

  #hide() {
    this.#open = false;
    this.#activeIndex = -1;
    this.#render();
  }

  /** @param {string} option */
  #select(option) {
    this.value = option;
    this.#onChange(option);
    this.#hide();
  }

  #render() {
    this.root.classList.toggle('open', this.#open);
    this.root.classList.toggle('disabled', this.#disabled);
    this.input.disabled = this.#disabled;
    this.toggleButton.disabled = this.#disabled;
    this.toggleButton.hidden = this.#options.length === 0 && !this.#loading;
    this.input.setAttribute('aria-expanded', String(this.#open));
    if (this.#activeIndex >= 0) {
      this.input.setAttribute('aria-activedescendant', this.#optionId(this.#activeIndex));
    } else {
      this.input.removeAttribute('aria-activedescendant');
    }

    this.list.hidden = !this.#open;
    if (!this.#open) return;

    const items = [];
    if (this.#loading) items.push(emptyItem('Namespaces ophalen…'));
    const filtered = this.#filtered();
    filtered.forEach((option, i) => {
      const li = document.createElement('li');
      li.id = this.#optionId(i);
      li.textContent = option;
      li.setAttribute('role', 'option');
      li.setAttribute('aria-selected', String(option === this.value));
      li.classList.toggle('active', i === this.#activeIndex);
      li.addEventListener('click', () => this.#select(option));
      li.addEventListener('mousemove', () => {
        if (this.#activeIndex === i) return;
        this.#activeIndex = i;
        this.#render();
      });
      items.push(li);
    });
    if (filtered.length === 0 && !this.#loading) {
      items.push(emptyItem('Niet in de lijst; je kunt hem gewoon zo gebruiken.'));
    }
    this.list.replaceChildren(...items);
  }

  /** @param {KeyboardEvent} event */
  #onKeydown(event) {
    const filtered = this.#filtered();
    const count = filtered.length;
    switch (event.key) {
      case 'ArrowDown':
      case 'ArrowUp': {
        event.preventDefault();
        if (!this.#open) {
          this.#show();
          return;
        }
        if (count === 0) return;
        const step = event.key === 'ArrowDown' ? 1 : -1;
        const current = this.#activeIndex;
        this.#activeIndex =
          current < 0 ? (step > 0 ? 0 : count - 1) : (current + step + count) % count;
        this.#render();
        document.getElementById(this.#optionId(this.#activeIndex))?.scrollIntoView({ block: 'nearest' });
        return;
      }
      case 'Enter':
        if (this.#open && this.#activeIndex >= 0 && !event.ctrlKey && !event.metaKey) {
          event.preventDefault();
          this.#select(filtered[this.#activeIndex]);
        }
        return;
      case 'Escape':
        if (this.#open) {
          event.preventDefault();
          this.#hide();
        }
        return;
    }
  }
}

/** @param {string} text */
function emptyItem(text) {
  const li = document.createElement('li');
  li.className = 'combobox-empty';
  li.textContent = text;
  return li;
}
