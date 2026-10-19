from typing import Any, Dict, Optional

import json

from cert_bypass import CertBypass
from injector import BootloaderInjector
from stage import PatchStage


class Device:
    def __init__(self, name: str, codename: str, stages: Dict[str, Any],
                 base: Optional[int] = None,
                 cert_bypass: Optional[CertBypass] = None,
                 **kwargs: Any) -> None:
        self.name: str = name
        self.codename: str = codename
        self.stages: Dict[str, Any] = stages
        self.base: Optional[int] = base
        self.cert_bypass: Optional[CertBypass] = cert_bypass
        self.device_opts: Dict[str, Any] = kwargs

    def _apply_expectations(self, injector: BootloaderInjector, path: str) -> Optional[bool]:
        """Attach per-partition hit-count expectations to the matching patch stages.

        Returns False when the expectations cannot be honoured, None otherwise.
        """
        try:
            with open(path, 'r') as f:
                expectations: Dict[str, Any] = json.load(f)
        except Exception as e:
            print("Error: could not read expectations file %s: %s" % (path, e))
            return False

        for stage_name, expected in expectations.items():
            stage = injector.stages.get(stage_name)
            if stage is None:
                print("Error: expectations reference unknown stage '%s'" % stage_name)
                return False
            if not isinstance(stage, PatchStage):
                print("Error: expectations reference non-patch stage '%s'" % stage_name)
                return False
            if not isinstance(expected, dict) or not all(
                isinstance(k, str) and isinstance(v, int) for k, v in expected.items()
            ):
                print("Error: expectations for '%s' must map partition names to counts" % stage_name)
                return False
            stage.expected_hits = dict(expected)

        return None

    def execute(self, args: Any) -> int:
        strict: bool = getattr(args, 'strict', False)
        injector: BootloaderInjector = BootloaderInjector(
            args.image,
            args.payload_dir,
            base=self.base,
            device_name=self.name,
            strict=strict
        )
        injector.stages = self.stages.copy()

        if args.config:
            injector.load_config(args.config)

        expect_hits: Optional[str] = getattr(args, 'expect_hits', None)
        if expect_hits:
            if self._apply_expectations(injector, expect_hits) is False:
                return 1

        if args.list_stages:
            print("Available stages for %s (%s):" % (self.name, self.codename))
            for stage_name in injector.list_stages():
                stage = injector.stages[stage_name]
                base_addr, pivot_addr = stage.get_addresses()
                status = "enabled" if stage.is_enabled() else "disabled"
                description = stage.get_description()
                desc_text = " - %s" % description if description else ""
                print("  %s: base=0x%X, pivot=0x%X (%s)%s" % (stage_name, base_addr, pivot_addr, status, desc_text))
            return 0

        if not injector.inject_all_stages():
            return 1

        if self.cert_bypass is not None:
            injector.apply_cert_bypass(self.cert_bypass)

        injector.save_patched_bootloader(args.output)
        return 0
