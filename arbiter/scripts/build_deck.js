// Builds ARBITER.pptx — the fifteen-minute deck.
//
// The palette and the motif are the terminal, because that is what the argument is made
// of: every slide carries real output from a real run, and the one thing the project
// claims is that a finding is a transcript rather than a sentence. A deck of bullets
// about execution evidence would be arguing against itself.
//
//   node scripts/build_deck.js

const pptxgen = require("pptxgenjs");
const path = require("path");

const INK = "12100E";       // near-black, the terminal ground
const PAPER = "1B1815";     // the panel evidence sits on
const TEXT = "D8D2C8";      // warm off-white
const MUTE = "8A8178";      // captions, labels
const BRASS = "C8B88A";     // the accent: code, numbers that matter
const PASS = "7FB069";      // something that held
const FAIL = "C1554E";      // something that was refused

const HEAD = "Cambria";     // safe list, renders true to width in QA
const BODY = "Calibri";
const MONO = "Courier New";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";           // 13.3 x 7.5 — set BEFORE any slide is added
pres.author = "ericchen913900";
pres.title = "ARBITER";

const W = 13.3, H = 7.5, M = 0.7;

// ---------------------------------------------------------------------------
function slide(opts = {}) {
  const s = pres.addSlide();
  s.background = { color: opts.bg || INK };
  return s;
}

function title(s, text, y = 0.55, color = TEXT) {
  s.addText(text, {
    x: M, y, w: W - 2 * M, h: 0.85, fontSize: 34, bold: true,
    fontFace: HEAD, color, align: "left", margin: 0,
  });
}

function kicker(s, text, y = 0.32) {
  s.addText(text.toUpperCase(), {
    x: M, y, w: W - 2 * M, h: 0.3, fontSize: 11, bold: true, charSpacing: 2,
    fontFace: BODY, color: BRASS, margin: 0,
  });
}

// A block of real terminal output. This is the deck's one repeated element.
function evidence(s, lines, o = {}) {
  const x = o.x ?? M, y = o.y ?? 2.0;
  const w = o.w ?? W - 2 * M, h = o.h ?? 3.2;
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w, h, fill: { color: PAPER }, rectRadius: 0.06,
    line: { color: "2A2622", width: 1 },
  });
  // Joined rather than passed as an array: pptxgenjs only accepts an array of
  // {text, options}, and silently is not the word for what it does with plain strings.
  s.addText(Array.isArray(lines) ? lines.join("\n") : lines, {
    x: x + 0.28, y: y + 0.22, w: w - 0.56, h: h - 0.44,
    fontSize: o.size ?? 14, fontFace: MONO, color: o.color ?? TEXT,
    margin: 0, valign: "top", lineSpacing: o.lead ?? 20,
  });
}

function note(s, text, y = H - 1.15) {
  s.addText(text, {
    x: M, y, w: W - 2 * M, h: 0.8, fontSize: 15, fontFace: BODY,
    color: MUTE, margin: 0, valign: "top",
  });
}

function stat(s, value, label, o = {}) {
  s.addText(value, {
    x: o.x, y: o.y, w: o.w, h: 1.15, fontSize: o.size ?? 62, bold: true,
    fontFace: HEAD, color: o.color ?? BRASS, margin: 0, align: "left",
  });
  s.addText(label, {
    x: o.x, y: o.y + 1.05, w: o.w, h: 0.9, fontSize: 14, fontFace: BODY,
    color: MUTE, margin: 0, align: "left", valign: "top",
  });
}

// ---------------------------------------------------------------------------
// 1. The claim
{
  const s = slide();
  s.addText("ARBITER", {
    x: M, y: 2.1, w: W - 2 * M, h: 1.0, fontSize: 54, bold: true,
    fontFace: HEAD, color: TEXT, margin: 0,
  });
  s.addText(
    [
      { text: "A finding is a ", options: { color: MUTE } },
      { text: "transcript of an execution", options: { color: BRASS, bold: true } },
      { text: ", not an assertion.", options: { color: MUTE } },
    ],
    { x: M, y: 3.2, w: W - 2 * M, h: 0.6, fontSize: 26, fontFace: HEAD, margin: 0 },
  );
  s.addText(
    "The model is not allowed to report a vulnerability. It has to write an attack, and " +
    "the harness compiles it and runs it on an EVM against a success condition the model never sees.",
    { x: M, y: 4.05, w: 9.6, h: 1.2, fontSize: 17, fontFace: BODY, color: TEXT, margin: 0, valign: "top" },
  );
  s.addText("AIS3 2026  ·  安全工具開發與研究自動化", {
    x: M, y: H - 1.0, w: 6, h: 0.4, fontSize: 13, fontFace: BODY, color: MUTE, margin: 0,
  });
  s.addNotes(
    "Say only this sentence. Do not say 'eight axioms', do not say victim_loss, do not " +
    "say MCC — the room does not have those words yet. Pause after 'never sees'.",
  );
}

// 2. The baseline's own scoreboard
{
  const s = slide();
  kicker(s, "the comparison everyone reaches for");
  title(s, "Bastet, 40 paired samples", 0.75);
  evidence(s, [
    "TP  20      TN   0      FP  20      FN   0",
    "",
    "precision  0.500     recall  1.000     F1  0.667",
  ], { y: 2.15, h: 2.0, size: 20, lead: 34 });
  note(s,
    "Their number, not ours. Nothing here is disputed — this is what their tool reported " +
    "on the forty samples, run verbatim on its own prompts.", 4.6);
  s.addNotes("Put this up and let it sit. Do not editorialise yet — the next slide does that.");
}

// 3. The translation
{
  const s = slide();
  kicker(s, "what that scoreboard means");
  title(s, "It answered “vulnerable” to all forty", 0.75);
  s.addText(
    "Twenty of them were the fixed versions.",
    { x: M, y: 1.95, w: W - 2 * M, h: 0.5, fontSize: 22, fontFace: HEAD, color: TEXT, margin: 0 },
  );
  s.addText(
    [
      { text: "Its F1 is 0.667 because a smoke alarm that is always going off\n", options: {} },
      { text: "is right every single time there is a fire.", options: {} },
    ],
    { x: M, y: 2.85, w: 11.5, h: 1.3, fontSize: 27, fontFace: HEAD, color: BRASS, margin: 0, lineSpacing: 38 },
  );
  stat(s, "0.000", "its MCC — correlation with the\ntruth, on the same forty samples",
       { x: M, y: 4.55, w: 4.2, color: FAIL });
  stat(s, "20 / 20", "flagged the bug — and flagged\nthe fix just as confidently",
       { x: 5.6, y: 4.55, w: 5.2, size: 54 });
  s.addNotes("The alarm line is the one they will remember. Say it, then stop talking.");
}

// 4. Per-detector — the strongest slide
{
  const s = slide();
  kicker(s, "why the aggregate is zero");
  title(s, "Scored one detector at a time", 0.75);
  evidence(s, [
    "detector                             pairs    V    S  both   discriminated",
    "SC03:2025 - Logic Errors                20   20   20    20         0",
    "SC04:2025 - Lack of Input Validation    20   20   20    20         0",
    "Refund failed                           20   20   20    20         0",
    "SC01:2025 - Improper Access Control     20   20   19    19         1",
    "Lack of access control   (best of 53)   20   19   16    16         3",
  ], { y: 1.85, h: 2.75, size: 13, lead: 22 });
  s.addText(
    [
      { text: "37 of 53", options: { color: BRASS, bold: true, fontSize: 22 } },
      { text: "  detectors never once fired on a bug and stayed quiet on its fix.",
        options: { color: TEXT, fontSize: 18 } },
    ],
    { x: M, y: 4.85, w: 11.9, h: 0.5, fontFace: BODY, margin: 0 },
  );
  note(s,
    "The ensemble carries no information because almost every part of it carries none. " +
    "Computed from their recorded run — it makes no claim about our tool at all.", 5.45);
  s.addNotes(
    "Strongest slide in the deck. It needs nothing from us and reruns in four seconds: " +
    "python3 scripts/adjudicability.py --jobs runs/h2h-bastet.jobs.jsonl",
  );
}

// 5. Nothing to run
{
  const s = slide();
  kicker(s, "and nobody can check any of it");
  title(s, "Their findings cannot be adjudicated", 0.75);
  stat(s, "1152", "findings produced across\n53 detectors, 40 samples", { x: M, y: 2.0, w: 4.5 });
  stat(s, "0", "carrying a contract, a test,\na transaction — anything runnable",
       { x: 5.4, y: 2.0, w: 5.6, color: FAIL });
  s.addText(
    "It is not that our judge rejects their findings. No judge can reach them.",
    { x: M, y: 4.35, w: 11.9, h: 0.6, fontSize: 24, fontFace: HEAD, color: BRASS, margin: 0 },
  );
  note(s,
    "Their output is prose: a summary, a severity, a function name, a description. " +
    "That is the gap this project is about — not accuracy, but what kind of object a finding is.",
    5.15);
  s.addNotes("This is the thesis restated as a measurement. Slow down here.");
}

// 6. Gates check themselves
{
  const s = slide();
  kicker(s, "demo · 30 seconds, no network, no key");
  title(s, "The gates check themselves", 0.75);
  evidence(s, [
    "victim           4/4 as expected      drain          2/2 as expected",
    "forgery          6/6 as expected      sweep          2/2 as expected",
    "halt             3/3 as expected      latebinding    4/4 as expected",
    "setup_forgery    3/3 as expected      gain           2/2 as expected",
  ], { y: 1.9, h: 2.1, size: 14, lead: 24, color: PASS });
  s.addText(
    "Each asserts in both directions — it refuses what it must, and still admits what it must not refuse.",
    { x: M, y: 4.2, w: 11.9, h: 0.6, fontSize: 19, fontFace: HEAD, color: TEXT, margin: 0 },
  );
  note(s,
    "A gate that only ever says no is not a gate, it is a broken tool. Every one of these " +
    "exists because the tool caught itself cheating.", 5.0);
  s.addNotes(
    "If asked for an example: an 'exploit' that drained scenery its own setup built; a " +
    "selfdestruct that halted before the predicate ran; a vm.store on the owner slot in setup.",
  );
}

// 7. Real chain
{
  const s = slide();
  kicker(s, "demo · a real chain, real keys, real gas");
  title(s, "Drained, in signed transactions", 0.75);
  evidence(s, [
    "queue drained        6.0000 ether",
    "attacker net         5.9999 ether   (put in 1, gas 231,081)",
    "victim shortfall     5.0000 ether",
    "",
    "PROVEN on a live chain: value left the contract, the attacker holds it,",
    "and an ordinary user who queued first cannot get theirs back.",
  ], { y: 1.9, h: 2.85, size: 14, lead: 24 });
  note(s,
    "Over JSON-RPC there is no vm.prank. To act as an account you hold its key, to spend " +
    "you have the balance, to be included you pay for gas. Nothing is left to forge.", 5.0);
  s.addNotes("Point at the gas number. It is the detail that makes it read as real.");
}

// 8. One line moved
{
  const s = slide();
  kicker(s, "demo · the same attack, one line moved");
  title(s, "…and it reverts", 0.75);
  s.addText("nonce[msg.sender] = n + 1;", {
    x: M, y: 1.8, w: 5.6, h: 0.45, fontSize: 15, fontFace: MONO, color: BRASS, margin: 0,
  });
  s.addText("written AFTER the transfer", {
    x: M, y: 2.25, w: 5.6, h: 0.35, fontSize: 13, fontFace: BODY, color: MUTE, margin: 0,
  });
  s.addText("written BEFORE the transfer", {
    x: 7.0, y: 2.25, w: 5.6, h: 0.35, fontSize: 13, fontFace: BODY, color: MUTE, margin: 0,
  });
  s.addText("nonce[msg.sender] = n + 1;", {
    x: 7.0, y: 1.8, w: 5.6, h: 0.45, fontSize: 15, fontFace: MONO, color: BRASS, margin: 0,
  });
  evidence(s, [
    "queue drained      6.0000",
    "attacker net      +5.9999",
    "victim shortfall   5.0000",
    "",
    "PROVEN",
  ], { x: M, y: 2.75, w: 5.6, h: 2.2, size: 14, lead: 22 });
  evidence(s, [
    "attack tx          REVERTED",
    "victim's claim     succeeded",
    "victim shortfall   0.0000",
    "",
    "NOT PROVEN",
  ], { x: 7.0, y: 2.75, w: 5.6, h: 2.2, size: 14, lead: 22, color: FAIL });
  note(s,
    "Identical attacker contract, identical accounts, identical amounts. An exploit that " +
    "drained both would never have been about the defect.", 5.2);
  s.addNotes("This pair is the whole argument. Do not rush it.");
}

// 9. The ladder
{
  const s = slide();
  kicker(s, "demo · how much scepticism a finding survived");
  title(s, "The evidence ladder", 0.75);
  const rungs = [
    ["1  synthetic", "our predicate, a negation test, eight gates",
     "the harness is still the EVM's administrator", MUTE],
    ["2  standalone", "the dumped project compiles and passes elsewhere",
     "nobody has to trust our summary", TEXT],
    ["3  live", "reproduced as signed transactions on a chain",
     "the administrator is gone: no cheatcodes exist", BRASS],
  ];
  rungs.forEach(([name, what, gave, col], i) => {
    const y = 1.95 + i * 1.15;
    s.addShape(pres.ShapeType.roundRect, {
      x: M, y, w: 11.9, h: 0.95, fill: { color: PAPER }, rectRadius: 0.06,
      line: { color: "2A2622", width: 1 },
    });
    s.addText(name, { x: M + 0.3, y: y + 0.12, w: 2.3, h: 0.35, fontSize: 17, bold: true,
                      fontFace: MONO, color: col, margin: 0 });
    s.addText(what, { x: M + 2.7, y: y + 0.10, w: 5.3, h: 0.38, fontSize: 14,
                      fontFace: BODY, color: TEXT, margin: 0 });
    s.addText(gave, { x: M + 2.7, y: y + 0.48, w: 8.6, h: 0.38, fontSize: 13,
                      fontFace: BODY, color: MUTE, margin: 0, italic: true });
  });
  s.addText(
    "Rung one is the only one that searches. Rung three cannot find anything at all — it can only refuse.",
    { x: M, y: 5.55, w: 11.9, h: 0.6, fontSize: 19, fontFace: HEAD, color: TEXT, margin: 0 },
  );
  s.addNotes(
    "Both of our false positives were refused at rung three on their merits — one left the " +
    "victim short while handing the attacker nothing, the other moved no value out of the " +
    "contract at all.",
  );
}

// 10. Our own ceiling
{
  const s = slide();
  kicker(s, "measured against ourselves");
  title(s, "What our own predicate cannot express", 0.75);
  evidence(s, [
    "the 35 reference exploits, under the predicate WE are graded with",
    "",
    "  expressible      8    proves the bug, refuses the fix",
    "  unharmed        13    attacker takes value — up to 9 ether — user still paid",
    "  uncredited       3    user loses, nobody holds it: griefing has no beneficiary",
    "  no_victim       10    no depositor exists: signature replay has no depositor",
    "  no_build         1    ours",
  ], { y: 1.85, h: 3.0, size: 13.5, lead: 22 });
  s.addText(
    [
      { text: "Our recall is bounded by 0.229", options: { color: BRASS, bold: true } },
      { text: ", not by 1.000 — and 26 of those 27 are the predicate being deliberately " +
              "stricter than “the attacker profited”.", options: { color: TEXT } },
    ],
    { x: M, y: 5.05, w: 11.9, h: 0.9, fontSize: 17, fontFace: BODY, margin: 0, valign: "top" },
  );
  s.addNotes(
    "Nobody asked us to measure this. It is the number that makes our recall interpretable, " +
    "and the baseline cannot produce its equivalent because it has no predicate to measure.",
  );
}

// 11. Where we actually are
{
  const s = slide();
  kicker(s, "three identical runs, same 70 samples");
  title(s, "The number I will not give you as one number", 0.75);
  evidence(s, [
    "run             TP  TN  FP  FN     prec     rec      f1     mcc",
    "fixed1           7  31   4  28    0.636   0.200   0.304   0.118",
    "fixed2          13  30   5  22    0.722   0.371   0.491   0.261",
    "casc2-strict    10  33   2  25    0.833   0.286   0.426   0.303",
    "                          mean    0.731   0.286   0.407   0.227",
  ], { y: 1.85, h: 2.35, size: 13.5, lead: 22 });
  s.addText(
    "MCC swings by a factor of two and a half between identical runs. I only know that because we ran it three times.",
    { x: M, y: 4.4, w: 11.9, h: 0.7, fontSize: 18, fontFace: HEAD, color: BRASS, margin: 0, valign: "top" },
  );
  s.addText(
    [
      { text: "Stable, per class: of 35 vulnerability classes we discriminate ", options: { color: TEXT } },
      { text: "8", options: { color: PASS, bold: true } },
      { text: " — flag the bug, stay quiet on the fix — against ", options: { color: TEXT } },
      { text: "0", options: { color: FAIL, bold: true } },
      { text: ".", options: { color: TEXT } },
    ],
    { x: M, y: 5.25, w: 11.9, h: 0.6, fontSize: 18, fontFace: BODY, margin: 0 },
  );
  s.addNotes(
    "Our own scoring code has always said every headline should be a mean over repeats. " +
    "It had been run with repeats of one, and the first thing measuring that produced was " +
    "a number I did not want.",
  );
}

// 12. Close
{
  const s = slide();
  kicker(s, "three sentences");
  const closes = [
    "A finding here is a transcript of an execution, and you can re-run every one of them without trusting a word I have said.",
    "Every gate exists because the tool caught itself cheating — draining scenery it had built, halting before the predicate ran, writing an owner slot in setup. Those are commits, not hypotheticals.",
    "And the one number that decides whether our recall means anything, we measured against ourselves and published.",
  ];
  closes.forEach((t, i) => {
    s.addText(t, {
      x: M, y: 1.5 + i * 1.55, w: 11.9, h: 1.3, fontSize: 21, fontFace: HEAD,
      color: i === 2 ? BRASS : TEXT, margin: 0, valign: "top", lineSpacing: 30,
    });
  });
  s.addText("github.com/ericchen913900/Aislop3   ·   arbiter/DEMO.html", {
    x: M, y: H - 0.95, w: 11.9, h: 0.4, fontSize: 13, fontFace: MONO, color: MUTE, margin: 0,
  });
  s.addNotes("Then stop. Do not add a summary slide after this one.");
}

const out = path.join(__dirname, "..", "ARBITER.pptx");
pres.writeFile({ fileName: out }).then(() => console.log("wrote", out));
