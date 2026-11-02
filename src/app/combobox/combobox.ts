import { Component, ElementRef, computed, input, model, signal, viewChild } from '@angular/core';

let nextId = 0;

/**
 * Text field with a filterable option list (WAI-ARIA combobox pattern).
 * Free text is allowed: the options are suggestions, not a restriction.
 */
@Component({
  selector: 'app-combobox',
  template: `
    <div class="combobox" [class.open]="open()" [class.disabled]="disabled()">
      <input
        #field
        type="text"
        role="combobox"
        autocomplete="off"
        spellcheck="false"
        aria-autocomplete="list"
        [id]="inputId()"
        [attr.aria-expanded]="open()"
        [attr.aria-controls]="listId"
        [attr.aria-activedescendant]="activeIndex() >= 0 ? optionId(activeIndex()) : null"
        [placeholder]="placeholder()"
        [disabled]="disabled()"
        [value]="value()"
        (input)="onInput($any($event.target).value)"
        (click)="show()"
        (keydown)="onKeydown($event)"
        (blur)="hide()"
      />
      @if (options().length > 0 || loading()) {
        <button
          type="button"
          class="combobox-toggle"
          tabindex="-1"
          aria-label="Toon namespaces"
          [disabled]="disabled()"
          (mousedown)="$event.preventDefault()"
          (click)="toggle()"
        >
          <svg viewBox="0 0 12 12" aria-hidden="true"><path d="M3 4.5 6 7.5 9 4.5" /></svg>
        </button>
      }
      @if (open()) {
        <ul class="combobox-list" role="listbox" [id]="listId" (mousedown)="$event.preventDefault()">
          @if (loading()) {
            <li class="combobox-empty">Namespaces ophalen…</li>
          }
          @for (option of filtered(); track option; let i = $index) {
            <li
              role="option"
              [id]="optionId(i)"
              [class.active]="i === activeIndex()"
              [attr.aria-selected]="option === value()"
              (click)="select(option)"
              (mousemove)="activeIndex.set(i)"
            >
              {{ option }}
            </li>
          } @empty {
            @if (!loading()) {
              <li class="combobox-empty">Niet in de lijst; je kunt hem gewoon zo gebruiken.</li>
            }
          }
        </ul>
      }
    </div>
  `,
})
export class Combobox {
  readonly value = model('');
  readonly options = input<string[]>([]);
  readonly disabled = input(false);
  readonly loading = input(false);
  readonly placeholder = input('');
  readonly inputId = input<string>();

  protected readonly listId = `combobox-list-${nextId++}`;
  protected readonly open = signal(false);
  protected readonly activeIndex = signal(-1);
  private readonly field = viewChild.required<ElementRef<HTMLInputElement>>('field');

  /** All options while the value is empty or already one of them; otherwise the matches. */
  protected readonly filtered = computed(() => {
    const options = this.options();
    const query = this.value().trim().toLowerCase();
    if (!query || options.includes(this.value().trim())) return options;
    return options.filter((o) => o.toLowerCase().includes(query));
  });

  protected optionId(index: number): string {
    return `${this.listId}-${index}`;
  }

  protected show(): void {
    if (this.disabled() || (this.options().length === 0 && !this.loading())) return;
    this.open.set(true);
    this.activeIndex.set(this.filtered().indexOf(this.value().trim()));
  }

  protected hide(): void {
    this.open.set(false);
    this.activeIndex.set(-1);
  }

  protected toggle(): void {
    if (this.open()) {
      this.hide();
    } else {
      this.field().nativeElement.focus();
      this.show();
    }
  }

  protected onInput(text: string): void {
    this.value.set(text);
    this.show();
    this.activeIndex.set(-1);
  }

  protected select(option: string): void {
    this.value.set(option);
    this.hide();
  }

  protected onKeydown(event: KeyboardEvent): void {
    const count = this.filtered().length;
    switch (event.key) {
      case 'ArrowDown':
      case 'ArrowUp': {
        event.preventDefault();
        if (!this.open()) {
          this.show();
          return;
        }
        if (count === 0) return;
        const step = event.key === 'ArrowDown' ? 1 : -1;
        const current = this.activeIndex();
        const next = current < 0 ? (step > 0 ? 0 : count - 1) : (current + step + count) % count;
        this.activeIndex.set(next);
        document.getElementById(this.optionId(next))?.scrollIntoView({ block: 'nearest' });
        return;
      }
      case 'Enter':
        if (this.open() && this.activeIndex() >= 0 && !event.ctrlKey && !event.metaKey) {
          event.preventDefault();
          this.select(this.filtered()[this.activeIndex()]);
        }
        return;
      case 'Escape':
        if (this.open()) {
          event.preventDefault();
          this.hide();
        }
        return;
    }
  }
}
