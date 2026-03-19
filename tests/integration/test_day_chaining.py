#!/usr/bin/env python3
"""
Day chaining tests extracted from test_gateway_pipeline.py
"""
from __future__ import annotations

import json


class TestDayChaining:
    """Test that day records chain correctly via prev_day_root."""

    def test_first_day_has_zero_prev_root(
        self,
        temp_workspace,
        sample_facts,
        write_sample_facts_fixture,
        run_merkle_batcher,
    ):
        write_sample_facts_fixture(temp_workspace["facts_dir"], sample_facts)
        # Run batcher for the first day
        rc = run_merkle_batcher(
            temp_workspace["facts_dir"],
            temp_workspace["out_dir"],
            "test-site",
            "2025-10-07",
        )
        assert rc == 0

        day_json_path = temp_workspace["out_dir"] / "day" / "2025-10-07.json"
        day_record = json.loads(day_json_path.read_text())

        # First day should have all-zero prev_day_root
        assert day_record["prev_day_root"] == "00" * 32

    def test_second_day_chains_to_first(
        self,
        temp_workspace,
        sample_facts,
        write_sample_facts_fixture,
        run_merkle_batcher,
    ):
        write_sample_facts_fixture(temp_workspace["facts_dir"], sample_facts)
        # Run first day
        rc1 = run_merkle_batcher(
            temp_workspace["facts_dir"],
            temp_workspace["out_dir"],
            "test-site",
            "2025-10-07",
        )
        assert rc1 == 0

        day1_json = temp_workspace["out_dir"] / "day" / "2025-10-07.json"
        day1_record = json.loads(day1_json.read_text())
        day1_root = day1_record["day_root"]

        # Run second day
        rc2 = run_merkle_batcher(
            temp_workspace["facts_dir"],
            temp_workspace["out_dir"],
            "test-site",
            "2025-10-08",
        )
        assert rc2 == 0

        day2_json = temp_workspace["out_dir"] / "day" / "2025-10-08.json"
        day2_record = json.loads(day2_json.read_text())

        # Second day's prev_day_root should match first day's day_root
        assert day2_record["prev_day_root"] == day1_root

    def test_day_chaining_ignores_other_site_days(
        self,
        temp_workspace,
        sample_facts,
        write_sample_facts_fixture,
        run_merkle_batcher,
    ):
        write_sample_facts_fixture(temp_workspace["facts_dir"], sample_facts)

        rc1 = run_merkle_batcher(
            temp_workspace["facts_dir"],
            temp_workspace["out_dir"],
            "site-a",
            "2025-10-06",
        )
        assert rc1 == 0
        day1_record = json.loads(
            (temp_workspace["out_dir"] / "day" / "2025-10-06.json").read_text()
        )
        site_a_root = day1_record["day_root"]

        rc2 = run_merkle_batcher(
            temp_workspace["facts_dir"],
            temp_workspace["out_dir"],
            "site-b",
            "2025-10-07",
        )
        assert rc2 == 0

        rc3 = run_merkle_batcher(
            temp_workspace["facts_dir"],
            temp_workspace["out_dir"],
            "site-a",
            "2025-10-08",
        )
        assert rc3 == 0

        day3_record = json.loads(
            (temp_workspace["out_dir"] / "day" / "2025-10-08.json").read_text()
        )
        assert day3_record["prev_day_root"] == site_a_root
