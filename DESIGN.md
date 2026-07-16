---
name: Codex Pool

description: A gilded private console for pooled AI access, setup, and analytics.
colors:
  void: "#050505"
  console: "#0e0e0e"
  code-well: "#080808"
  ink: "#e0e0e0"
  muted-ink: "#858585"
  subtle-ink: "#a0a0a0"
  disabled-ink: "#737373"
  gilded: "#d4af37"
  aged-gold: "#a98b47"
  outer-rule: "#1a1a1a"
  inner-rule: "#252525"
  strong-rule: "#333333"
  success: "#27ae60"
  error: "#c0392b"
typography:
  display:
    fontFamily: "Cormorant Garamond, Georgia, serif"
    fontSize: "2rem"
    fontWeight: 400
    lineHeight: 1.1
    letterSpacing: "normal"
  title:
    fontFamily: "Cormorant Garamond, Georgia, serif"
    fontSize: "1.35rem"
    fontWeight: 400
    lineHeight: 1.2
    letterSpacing: "normal"
  body:
    fontFamily: "Space Mono, ui-monospace, monospace"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.65
    letterSpacing: "normal"
  label:
    fontFamily: "Space Mono, ui-monospace, monospace"
    fontSize: "0.7rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.14em"
rounded:
  control: "2px"
  shell: "4px"
  field: "6px"
  panel: "8px"
  chip: "10px"
  group: "12px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "40px"
components:
  button-primary:
    backgroundColor: "{colors.gilded}"
    textColor: "{colors.void}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "12px 20px"
  button-secondary:
    backgroundColor: "{colors.console}"
    textColor: "{colors.muted-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "12px 20px"
  input:
    backgroundColor: "{colors.code-well}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.field}"
    padding: "12px 14px"
  panel:
    backgroundColor: "{colors.console}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "16px"
---

## Overview

**Creative North Star: The Gilded Console.** The interface is a private technical instrument housed in blackened metal: ceremonial at entry, exact once opened. Gold signals permission, selection, and valuable state; it is never general decoration. The shell can feel tactile and mechanical, but the work inside it must remain direct enough for a technical, impatient user.

**The Threshold Rule.** The login may feel rarefied and deliberate. After authentication, hierarchy shifts toward operation: setup path first, commands second, diagnostics and raw configuration on demand.

**The Quiet Until Selected Rule.** Inactive controls recede into the console. One current path receives the decisive gilded treatment. Never distribute equal visual weight across every choice.

Desktop uses a restrained centered shell with a persistent left navigation rail. Mobile turns that rail into an explicit grouped path selector and keeps every command, table, and status surface within the viewport. Spacing varies by function: compact inside controls, deliberate between setup steps, and generous around the heraldic identity.

## Colors

The system is built from near-black tonal layers and one aged metallic accent. Provider and status colors may appear in analytics, but they are data vocabulary rather than brand colors.

- **Primary:** Gilded is the active-selection and primary-action color. Aged Gold handles quiet ornament, secondary labels, and metallic edge cues.
- **Neutral:** Void is the page field; Console is the main shell; Code Well is reserved for commands and raw configuration. Ink is primary text, Muted Ink is tertiary text, and the two rule colors separate interactive objects without bright outlines.
- **Semantic:** Success and Error are reserved for actual state. Warnings use an amber distinct from the brand gold when confusion is possible.

**The Gold Has Meaning Rule.** Gold always means access, current selection, primary action, or a deliberately precious detail. If every heading and border is gold, the hierarchy has failed.

**The Black Is Layered Rule.** Separate surfaces through small tonal steps, inset treatment, and whitespace. Do not solve every grouping with a new bordered card.

## Typography

**Display Font:** Cormorant Garamond (with Georgia and serif fallback)

**Body Font:** Space Mono (with a native monospace fallback)

**Label/Mono Font:** Space Mono

**Character:** Cormorant carries the club's ceremonial voice in page titles and the friend mark. Space Mono makes setup instructions, controls, status, and analytics feel exact and inspectable. The contrast between them is the identity; do not introduce a third family.

### Hierarchy

- **Display** (400, 2rem, 1.1): login title and the authenticated page title only.
- **Headline** (400, approximately 1.6rem, 1.15): major entry or empty-state moments.
- **Title** (400, 1.35rem, 1.2): setup sections and analytics groups.
- **Body** (400, 0.875rem, 1.65): explanations and operational guidance, capped near 70 characters where prose runs long.
- **Label** (700, 0.7rem, 0.14em, uppercase): navigation groups, field labels, small actions, and compact metadata.

**The Split Voice Rule.** Serif is ceremonial; monospace is operational. Display type is forbidden in buttons, tabs, data labels, and code-adjacent UI.

## Elevation

Depth is tactile and mechanical. The outer console uses broad ambient darkness and a fine metallic edge. Interactive wells use inset shadows; selected controls may use a restrained outset highlight. Internal layout regions stay mostly tonal so the page does not become a stack of floating SaaS cards.

### Shadow Vocabulary

- **Console ambient** (`0 20px 50px rgba(0,0,0,0.8), 0 0 100px rgba(0,0,0,0.5)`): the single outer shell against the void.
- **Recessed well** (`inset 2px 2px 5px rgba(0,0,0,0.8), inset -1px -1px 1px rgba(255,255,255,0.05)`): fields, command wells, and mechanically inset controls.
- **Raised control** (`5px 5px 10px rgba(0,0,0,0.5), -1px -1px 1px rgba(255,255,255,0.03)`): selected or actionable controls only.

**The One Shell Rule.** The page may have one ambiently elevated container. Nested layout regions must use tone, spacing, or inset depth instead of another large shadow.

## Components

### Buttons

Buttons are compact mechanical controls, not promotional calls to action.

- **Shape:** nearly square edges (2px) with enough internal padding for a 44px touch target where used as a primary action.
- **Primary:** gilded face, void text, uppercase mono label, and a restrained raised treatment.
- **Hover / Focus:** brighten the metallic face slightly and show an unmistakable focus outline without changing geometry. State transitions stay between 150 and 250ms.
- **Secondary:** console or code-well surface with muted ink; it becomes brighter only on hover or selection.
- **Disabled:** visibly recessed, lower contrast, and non-interactive; never communicate disabled state through opacity alone.

### Chips

Chips are reserved for model names, providers, compact filters, and status. They use small tinted semantic backgrounds with readable text and rounded capsules only where the item is genuinely atomic. Do not turn ordinary metadata into pills.

### Cards / Containers

- **Corner Style:** restrained curves from 4px to 8px; 12px belongs to grouped navigation or a truly distinct interactive object.
- **Background:** console and code-well tonal layers.
- **Shadow Strategy:** inset for wells, flat for layout groups, ambient only for the outer shell.
- **Border:** one-pixel dark rules on interactive and data objects, not around every page section.
- **Internal Padding:** 16px for compact objects, 24px for major setup steps.

### Inputs / Fields

- **Style:** code-well background, one-pixel inner rule, 6px corners, mono text, explicit label above.
- **Focus:** gilded border or outline with sufficient separation from the dark field.
- **Error / Disabled:** pair semantic color with concise text or iconography; never rely on red or dimming alone.

### Navigation

Desktop navigation is a quiet vertical index with grouped labels and one gilded active item. Mobile navigation becomes a grouped two-column selector that keeps all setup paths visible without horizontal scrolling. Hover is subtle; selection is decisive. Navigation labels remain monospace and operational.

### Command Wells

Command wells are the signature operational component. They are recessed, copyable, syntax-preserving surfaces with a small action aligned away from the command text. Long lines wrap or scroll within the well without widening the page. Copy feedback is immediate and temporary.

## Do's and Don'ts

### Do:

- **Do** preserve the black, gold, heraldic, terminal-adjacent identity while making setup faster to scan.
- **Do** reserve Gilded for permission, current selection, primary actions, and valuable state.
- **Do** keep the shortest copy-paste setup path before manual configuration.
- **Do** use Cormorant Garamond for ceremony and Space Mono for operation.
- **Do** make commands, controls, errors, and live usage data readily legible even when decorative text remains low-light.
- **Do** show reduced-motion alternatives and preserve keyboard focus across every interactive component.

### Don't:

- **Don't** resemble a generic AI dashboard with interchangeable rounded cards, neon gradients, decorative glass, oversized hero metrics, excessive pills, or a template-like SaaS shell.
- **Don't** flatten the private-club identity into conventional admin software.
- **Don't** let visual novelty obscure setup instructions or make live pool data feel ornamental rather than trustworthy.
- **Don't** use gradient text. Metallic gradients may describe a physical control face or hairline, never letterforms.
- **Don't** wrap every section in a bordered, rounded, shadowed card. If whitespace and type establish the group, remove the container.
- **Don't** use display typography in buttons, navigation, labels, tables, or status UI.
- **Don't** use gold as a generic decorative separator; when everything glints, nothing is selected.
