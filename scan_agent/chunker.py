from dataclasses import dataclass, field

MAX_TOKENS_PER_CHUNK = 6000


@dataclass
class Chunk:
    files: list[str] = field(default_factory=list)
    code: str = ""
    estimated_tokens: int = 0


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 3)


def _split_large_file(file_path: str, content: str, max_tokens: int) -> list[tuple[str, str]]:
    lines = content.split("\n")
    if not lines:
        return []

    chunks: list[tuple[str, str]] = []
    current_lines: list[str] = []
    current_tokens = 0
    section_index = 1

    for line in lines:
        line_tokens = estimate_tokens(line)
        if current_tokens + line_tokens > max_tokens and current_lines:
            label = f"{file_path} [part {section_index}]"
            chunks.append((label, "\n".join(current_lines)))
            section_index += 1
            current_lines = []
            current_tokens = 0
        current_lines.append(line)
        current_tokens += line_tokens

    if current_lines:
        label = f"{file_path} [part {section_index}]" if section_index > 1 else file_path
        chunks.append((label, "\n".join(current_lines)))

    return chunks


def chunk_files(files: list[tuple[str, str]], max_tokens: int = MAX_TOKENS_PER_CHUNK) -> list[Chunk]:
    chunks: list[Chunk] = []
    current_chunk = Chunk()

    for path, content in files:
        tokens = estimate_tokens(content)

        if tokens > max_tokens:
            if current_chunk.files:
                chunks.append(current_chunk)
                current_chunk = Chunk()

            for label, part_content in _split_large_file(path, content, max_tokens):
                chunks.append(Chunk(files=[label], code=part_content, estimated_tokens=estimate_tokens(part_content)))
            continue

        if current_chunk.estimated_tokens + tokens > max_tokens:
            chunks.append(current_chunk)
            current_chunk = Chunk()

        current_chunk.files.append(path)
        if current_chunk.code:
            current_chunk.code += "\n\n" + f"# === File: {path} ===\n" + content
        else:
            current_chunk.code = f"# === File: {path} ===\n" + content
        current_chunk.estimated_tokens += tokens

    if current_chunk.files:
        chunks.append(current_chunk)

    return chunks
