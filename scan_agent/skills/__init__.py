from .base import BaseSkill, SkillFinding
from .secrets_detection import SecretsDetectionSkill
from .injection_detection import InjectionDetectionSkill
from .fastapi_security import FastAPISecuritySkill
from .auth_security import AuthSecuritySkill
from .file_security import FileSecuritySkill

BUILTIN_SKILLS: list[type[BaseSkill]] = [
    SecretsDetectionSkill,
    InjectionDetectionSkill,
    FastAPISecuritySkill,
    AuthSecuritySkill,
    FileSecuritySkill,
]


def discover_skills() -> list[BaseSkill]:
    instances: list[BaseSkill] = []
    for cls in BUILTIN_SKILLS:
        instances.append(cls())
    return instances


def get_skill_map() -> dict[str, BaseSkill]:
    result: dict[str, BaseSkill] = {}
    for s in discover_skills():
        result[s.name] = s
    return result


__all__ = [
    "BaseSkill",
    "SkillFinding",
    "discover_skills",
    "get_skill_map",
    "BUILTIN_SKILLS",
]
