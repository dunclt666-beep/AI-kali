"""Convert docs/bao_cao_3.4_3.5.md into a Word document with report formatting."""
from __future__ import annotations

import os
import re

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

BASE = os.path.dirname(os.path.abspath(__file__))
MD_PATH = os.path.join(BASE, "bao_cao_3.4_3.5.md")
DOCX_PATH = os.path.join(BASE, "bao_cao_3.4_3.5.docx")

BODY_FONT = "Times New Roman"
CODE_FONT = "Consolas"
BODY_SIZE = Pt(13)
TABLE_SIZE = Pt(11)
CODE_SIZE = Pt(10)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------
def set_run_font(run, name: str = BODY_FONT, size: Pt = BODY_SIZE, bold: bool = False,
                 italic: bool = False, color: RGBColor | None = None):
    run.font.name = name
    run.font.size = size
    run.bold = bold
    run.italic = italic
    if color is not None:
        run.font.color.rgb = color
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:ascii"), name)
    rfonts.set(qn("w:hAnsi"), name)
    rfonts.set(qn("w:eastAsia"), name)
    rfonts.set(qn("w:cs"), name)


def add_runs(paragraph, text: str, size: Pt = BODY_SIZE, base_bold: bool = False,
             base_italic: bool = False, color: RGBColor | None = None):
    """Add inline runs supporting **bold** and `code` spans."""
    pos = 0
    tokens = []
    pattern = re.compile(r"(\*\*|`)")
    while pos < len(text):
        match = pattern.search(text, pos)
        if not match:
            tokens.append(("text", text[pos:]))
            break
        if match.start() > pos:
            tokens.append(("text", text[pos:match.start()]))
        marker = match.group(1)
        end = text.find(marker, match.end())
        if end == -1:
            tokens.append(("text", text[match.start():]))
            break
        inner = text[match.end():end]
        tokens.append(("bold" if marker == "**" else "code", inner))
        pos = end + len(marker)

    for kind, value in tokens:
        if not value:
            continue
        run = paragraph.add_run(value)
        if kind == "bold":
            set_run_font(run, BODY_FONT, size, bold=True, italic=base_italic, color=color)
        elif kind == "code":
            set_run_font(run, CODE_FONT, Pt(size.pt - 1.5), bold=base_bold, italic=base_italic,
                         color=RGBColor(0x0B, 0x3B, 0x6B))
        else:
            set_run_font(run, BODY_FONT, size, bold=base_bold, italic=base_italic, color=color)


def shade(element, fill: str):
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    element.append(shd)


def shade_paragraph(paragraph, fill: str):
    ppr = paragraph._p.get_or_add_pPr()
    shade(ppr, fill)


def shade_cell(cell, fill: str):
    tcpr = cell._tc.get_or_add_tcPr()
    shade(tcpr, fill)


def add_page_number_footer(section):
    footer = section.footer
    paragraph = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_before = Pt(0)
    paragraph.paragraph_format.space_after = Pt(0)

    run = paragraph.add_run("Trang ")
    set_run_font(run, BODY_FONT, Pt(11))

    def field(instr: str):
        r = paragraph.add_run()
        set_run_font(r, BODY_FONT, Pt(11))
        begin = OxmlElement("w:fldChar")
        begin.set(qn("w:fldCharType"), "begin")
        instr_el = OxmlElement("w:instrText")
        instr_el.set(qn("xml:space"), "preserve")
        instr_el.text = instr
        end = OxmlElement("w:fldChar")
        end.set(qn("w:fldCharType"), "end")
        r._r.append(begin)
        r._r.append(instr_el)
        r._r.append(end)

    field(" PAGE ")
    run = paragraph.add_run(" / ")
    set_run_font(run, BODY_FONT, Pt(11))
    field(" NUMPAGES ")


def configure_styles(doc: Document):
    normal = doc.styles["Normal"]
    normal.font.name = BODY_FONT
    normal.font.size = BODY_SIZE
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.5
    rpr = normal.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:ascii"), BODY_FONT)
    rfonts.set(qn("w:hAnsi"), BODY_FONT)
    rfonts.set(qn("w:eastAsia"), BODY_FONT)
    rfonts.set(qn("w:cs"), BODY_FONT)

    heading_specs = {
        "Heading 1": (Pt(16), True, Pt(12), Pt(8)),
        "Heading 2": (Pt(14), True, Pt(10), Pt(6)),
        "Heading 3": (Pt(13), True, Pt(8), Pt(4)),
    }
    for name, (size, bold, before, after) in heading_specs.items():
        style = doc.styles[name]
        style.font.name = BODY_FONT
        style.font.size = size
        style.font.bold = bold
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.paragraph_format.space_before = before
        style.paragraph_format.space_after = after
        style.paragraph_format.line_spacing = 1.3
        style.paragraph_format.keep_with_next = True
        rpr = style.element.get_or_add_rPr()
        rfonts = rpr.find(qn("w:rFonts"))
        if rfonts is None:
            rfonts = OxmlElement("w:rFonts")
            rpr.append(rfonts)
        rfonts.set(qn("w:ascii"), BODY_FONT)
        rfonts.set(qn("w:hAnsi"), BODY_FONT)
        rfonts.set(qn("w:eastAsia"), BODY_FONT)
        rfonts.set(qn("w:cs"), BODY_FONT)


def body_paragraph(doc: Document, text: str, first_line: bool = True, center: bool = False):
    paragraph = doc.add_paragraph()
    fmt = paragraph.paragraph_format
    fmt.line_spacing = 1.5
    fmt.space_after = Pt(6)
    if center:
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fmt.first_line_indent = Cm(0)
    elif first_line:
        paragraph.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        fmt.first_line_indent = Cm(1.0)
    else:
        paragraph.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        fmt.first_line_indent = Cm(0)
    add_runs(paragraph, text)
    return paragraph


# ---------------------------------------------------------------------------
# Markdown parsing
# ---------------------------------------------------------------------------
def is_table_separator(line: str) -> bool:
    return bool(re.fullmatch(r"\|[\s:\-|]+\|", line.strip()))


def parse_table_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def add_table(doc: Document, rows: list[list[str]]):
    n_cols = max(len(row) for row in rows)
    table = doc.add_table(rows=len(rows), cols=n_cols)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True
    size = TABLE_SIZE if n_cols <= 4 else Pt(10)

    for r_idx, row in enumerate(rows):
        for c_idx in range(n_cols):
            cell = table.cell(r_idx, c_idx)
            cell.text = ""
            paragraph = cell.paragraphs[0]
            paragraph.paragraph_format.space_before = Pt(2)
            paragraph.paragraph_format.space_after = Pt(2)
            paragraph.paragraph_format.line_spacing = 1.1
            paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
            value = row[c_idx] if c_idx < len(row) else ""
            add_runs(paragraph, value, size=size, base_bold=(r_idx == 0))
            if r_idx == 0:
                shade_cell(cell, "D9E2F3")
            elif r_idx % 2 == 0:
                shade_cell(cell, "F5F8FC")
    return table


def add_image(doc: Document, alt: str, rel_path: str):
    image_path = os.path.join(BASE, rel_path)
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_before = Pt(6)
    paragraph.paragraph_format.space_after = Pt(2)
    if os.path.exists(image_path):
        run = paragraph.add_run()
        run.add_picture(image_path, width=Cm(16))
    else:
        set_run_font(paragraph.add_run(f"[Thiếu hình: {alt}]"), BODY_FONT, Pt(11), italic=True,
                     color=RGBColor(0xC0, 0x00, 0x00))
    caption = doc.add_paragraph()
    caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
    caption.paragraph_format.space_after = Pt(10)
    caption.paragraph_format.line_spacing = 1.15
    add_runs(caption, alt, size=Pt(11), base_italic=True)
    # Keep caption with figure
    caption.paragraph_format.keep_with_next = False


def add_code_block(doc: Document, lines: list[str]):
    for line in lines:
        paragraph = doc.add_paragraph()
        fmt = paragraph.paragraph_format
        fmt.space_before = Pt(0)
        fmt.space_after = Pt(0)
        fmt.line_spacing = 1.0
        fmt.left_indent = Cm(0.5)
        paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
        shade_paragraph(paragraph, "F2F2F2")
        run = paragraph.add_run(line if line else " ")
        set_run_font(run, CODE_FONT, CODE_SIZE)


def add_quote(doc: Document, text: str):
    paragraph = doc.add_paragraph()
    fmt = paragraph.paragraph_format
    fmt.left_indent = Cm(0.8)
    fmt.right_indent = Cm(0.5)
    fmt.space_before = Pt(6)
    fmt.space_after = Pt(8)
    fmt.line_spacing = 1.3
    paragraph.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    shade_paragraph(paragraph, "FFF7ED")
    add_runs(paragraph, text, size=Pt(12), base_italic=False)


def add_list_item(doc: Document, text: str, ordered: bool):
    paragraph = doc.add_paragraph()
    fmt = paragraph.paragraph_format
    fmt.left_indent = Cm(1.0)
    fmt.first_line_indent = Cm(-0.6)
    fmt.space_before = Pt(0)
    fmt.space_after = Pt(6)
    fmt.line_spacing = 1.4
    paragraph.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    prefix = "" if ordered else "•  "
    if ordered:
        add_runs(paragraph, text)
    else:
        run = paragraph.add_run(prefix)
        set_run_font(run, BODY_FONT, BODY_SIZE)
        add_runs(paragraph, text)


def convert():
    with open(MD_PATH, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()

    doc = Document()
    configure_styles(doc)

    section = doc.sections[0]
    section.page_width = Cm(21.0)
    section.page_height = Cm(29.7)
    section.top_margin = Cm(2.0)
    section.bottom_margin = Cm(2.0)
    section.left_margin = Cm(3.0)
    section.right_margin = Cm(2.0)
    add_page_number_footer(section)

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped == "---":
            doc.add_page_break()
            i += 1
            continue

        # Fenced code blocks
        if stripped.startswith("```"):
            code_lines: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i].rstrip())
                i += 1
            i += 1
            add_code_block(doc, code_lines)
            continue

        # Headings
        heading_match = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if heading_match:
            level = len(heading_match.group(1))
            text = heading_match.group(2).strip()
            paragraph = doc.add_heading(level=min(level, 3))
            add_runs(paragraph, text, size=Pt({1: 16, 2: 14, 3: 13}[min(level, 3)]), base_bold=True)
            i += 1
            continue

        # Images
        image_match = re.match(r"^!\[(.*?)\]\((.*?)\)$", stripped)
        if image_match:
            add_image(doc, image_match.group(1), image_match.group(2))
            i += 1
            continue

        # Tables
        if stripped.startswith("|") and i + 1 < len(lines) and is_table_separator(lines[i + 1].strip()):
            rows: list[list[str]] = [parse_table_row(stripped)]
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(parse_table_row(lines[i].strip()))
                i += 1
            add_table(doc, rows)
            continue

        # Blockquote
        if stripped.startswith(">"):
            add_quote(doc, stripped.lstrip(">").strip())
            i += 1
            continue

        # Bullet list
        bullet_match = re.match(r"^-\s+(.*)$", stripped)
        if bullet_match:
            add_list_item(doc, bullet_match.group(1).strip(), ordered=False)
            i += 1
            continue

        # Ordered list
        ordered_match = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if ordered_match:
            add_list_item(doc, f"{ordered_match.group(1)}. {ordered_match.group(2).strip()}", ordered=True)
            i += 1
            continue

        # Table / figure captions
        if re.match(r"^\*\*Bảng\s+\d+\.\d+\.", stripped):
            paragraph = doc.add_paragraph()
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            paragraph.paragraph_format.space_before = Pt(8)
            paragraph.paragraph_format.space_after = Pt(3)
            paragraph.paragraph_format.line_spacing = 1.15
            paragraph.paragraph_format.keep_with_next = True
            add_runs(paragraph, stripped, size=Pt(12), base_bold=True)
            i += 1
            continue

        # Pure formula lines: `... = ...`
        if stripped.startswith("`") and stripped.endswith("`") and "=" in stripped and stripped.count("`") == 2:
            paragraph = doc.add_paragraph()
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            paragraph.paragraph_format.space_before = Pt(4)
            paragraph.paragraph_format.space_after = Pt(6)
            paragraph.paragraph_format.line_spacing = 1.3
            add_runs(paragraph, stripped)
            i += 1
            continue

        # Normal paragraph
        body_paragraph(doc, stripped)
        i += 1

    doc.core_properties.title = "Thiết kế mô hình AI, cơ sở dữ liệu và giao diện"
    doc.core_properties.subject = "Báo cáo hệ thống AI Early Web Attack Detection"
    doc.save(DOCX_PATH)
    print("Saved", DOCX_PATH)


if __name__ == "__main__":
    convert()
