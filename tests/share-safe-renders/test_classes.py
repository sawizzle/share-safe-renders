# -*- coding: utf-8 -*-
"""One test group per class in the contract: K1 K2 K3 P1 P2 P3 G1 H1 H2 H3 M1, plus clean controls."""
import unittest

from _base import ScanCase, B, scan


class Helpers(object):
    def png_prompt(self, extra, text=None):
        kw = {} if text is None else {"text": text}
        return B.make_png(B.t_text("prompt", B.jdump(B.api_prompt(extra, **kw))))

    def png_workflow(self, nodes):
        return B.make_png(B.t_text("workflow", B.jdump(B.ui_workflow(nodes))))

    def note(self, nid, text):
        return {str(nid): B.api_node("Note", {"text": text})}


class TestK1(ScanCase, Helpers):
    NAMES = ("openai_legacy", "openai_old", "openai_proj", "anthropic", "github_classic", "github_fine", "aws",
             "google", "slack_bot", "slack_user", "stripe_live", "hf")

    def test_every_vendor_format(self):
        for name in self.NAMES:
            tok = getattr(self.fake, name)()
            rp = self.inproc(self.write(name + ".png", self.png_prompt(self.note(12, "key is " + tok))))
            hits = self.prim(rp, "K1")
            self.assertTrue(hits, name)
            h = hits[0]
            self.assertEqual(h["node_id"], "12", name)
            self.assertEqual(h["length"], len(tok), name)
            self.assertEqual(h["sha256_prefix"], scan.sha8(tok), name)
            self.assertEqual(h["carrier"], "png:tEXt")
            self.assertEqual(self.code_of(rp), 1)

    def test_not_flagged(self):
        f = self.fake
        for tok in (f.stripe_test(), "task-list-of-the-day-mask-image", "risk-assessment-for-the-new-desk-lamp",
                    "AK" + "IAIOSFODNN7" + "EXAMPLE", "h" + "f_hub_download"):
            rp = self.inproc(self.write("n.png", self.png_prompt(self.note(3, "see " + tok))))
            self.assertEqual(self.prim(rp, "K1"), [], tok)

    def test_hyphenated_prose_after_sk_is_not_a_key(self):
        for t in (" sk-learn-pipeline-for-images-v2 ", "(sk-8-bit-color-depth-explained)", "sk-and-more-words-here-now"):
            rp = self.inproc(self.write("n.png", self.png_prompt(self.note(3, "see" + t))))
            self.assertEqual(self.prim(rp, "K1"), [], t)

    def test_low_entropy_fakes_with_a_distinctive_prefix_are_still_found(self):
        for tok in ("gh" + "p_" + "a" * 36, "sk" + "-" + "A" * 48, "hf" + "_" + "x" * 34, "AKIA" + "A" * 16,
                    "xo" + "xb-" + "1" * 12 + "-" + "2" * 12 + "-" + "z" * 24, "sk" + "_live_" + "q" * 24):
            rp = self.inproc(self.write("n.png", self.png_prompt(self.note(3, "k " + tok))))
            self.assertEqual([x["sha256_prefix"] for x in self.prim(rp, "K1")], [scan.sha8(tok)], tok[:5])

    def test_same_secret_in_two_chunks_is_reported_in_both(self):
        tok = self.fake.hf()
        png = B.make_png(B.t_text("prompt", B.jdump(B.api_prompt(self.note(3, tok)))), B.t_text("Comment", "free " + tok),
                         B.i_text("Description", "again " + tok))
        rp = self.inproc(self.write("n.png", png))
        self.assertEqual(sorted(x["carrier"] for x in self.prim(rp, "K1")), ["png:iTXt", "png:tEXt", "png:tEXt"])

    def test_key_inside_longer_run_is_not_a_key(self):
        blob = "A" * 30 + self.fake.openai_legacy() + "B" * 30
        rp = self.inproc(self.write("n.png", self.png_prompt(self.note(3, blob))))
        self.assertEqual(self.prim(rp, "K1"), [])


class TestK2(ScanCase, Helpers):
    def test_api_format_inputs(self):
        pw = self.fake.secret_value()
        rp = self.inproc(self.write("a.png", self.png_prompt({"7": B.api_node("Loader", {"api_key": pw})})))
        h = self.prim(rp, "K2")
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["node_id"], "7")
        self.assertEqual(h[0]["sha256_prefix"], scan.sha8(pw))
        self.assertIn("field=api_key", h[0]["detail"])

    def test_ui_named_widget(self):
        pw = self.fake.secret_value()
        n = B.ui_node(5, "SomeLoader", ["plain", pw], names=["ckpt_name", "access_token"])
        rp = self.inproc(self.write("u.png", self.png_workflow([n])))
        h = self.prim(rp, "K2")
        self.assertEqual([x["node_id"] for x in h], ["5"])
        self.assertEqual(h[0]["sha256_prefix"], scan.sha8(pw))

    def test_ui_control_after_generate_does_not_shift_names(self):
        pw = self.fake.secret_value()
        n = B.ui_node(5, "Sampler", [123, "randomize", pw], names=["seed", "password"])
        rp = self.inproc(self.write("u.png", self.png_workflow([n])))
        self.assertEqual(len(self.prim(rp, "K2")), 1)

    def test_ui_title_names_the_field_when_widget_names_are_missing(self):
        pw = self.fake.secret_value()
        rp = self.inproc(self.write("t.png", self.png_workflow([B.ui_node(6, "PrimitiveString", [pw], title="OpenAI API Key")])))
        self.assertEqual([x["node_id"] for x in self.prim(rp, "K2")], ["6"])
        rp = self.inproc(self.write("t2.png", self.png_workflow([B.ui_node(6, "PrimitiveString", [pw], title="Seed value")])))
        self.assertEqual(self.prim(rp, "K2"), [])
        rp = self.inproc(self.write("t3.png", self.png_workflow([B.ui_node(6, "PrimitiveString", ["a long secret sentence about nothing"],
                                                                         title="Secret Santa notes")])))
        self.assertEqual(self.prim(rp, "K2"), [])

    def test_api_node_with_a_bypass_mode_is_flagged_h1(self):
        pw = self.fake.secret_value()
        node = B.api_node("Loader", {"password": pw})
        node["mode"] = 4
        rp = self.inproc(self.write("m.png", self.png_prompt({"7": node})))
        self.assertEqual(len(self.comp(rp, "H1")), 1)

    def test_ui_unnamed_positional_uses_node_type_hint_only(self):
        pw = self.fake.secret_value()
        rp = self.inproc(self.write("u.png", self.png_workflow([B.ui_node(6, "ApiKeyInput", [pw])])))
        h = self.prim(rp, "K2")
        self.assertEqual(len(h), 1)
        self.assertIn("unrecovered", h[0]["detail"])
        rp = self.inproc(self.write("u2.png", self.png_workflow([B.ui_node(6, "TextBox", [pw])])))
        self.assertEqual(self.prim(rp, "K2"), [])

    def test_free_json_and_name_variants(self):
        f = self.fake
        for key in ("password", "apiKey", "OPENAI_API_KEY", "client_secret", "Authorization", "bearer", "hf_token",
                    "auth_token_comfy_org", "secretAccessKey"):
            val = f.secret_value()
            body = B.jdump({"settings": {"a": [{key: val}]}})
            rp = self.inproc(self.write("j.png", B.make_png(B.t_text("settings", body))))
            h = self.prim(rp, "K2")
            self.assertEqual([x["sha256_prefix"] for x in h], [scan.sha8(val)], key)

    def test_duplicate_keys_do_not_hide_the_first_value(self):
        val = self.fake.secret_value()
        body = '{"api_key": "%s", "api_key": "x"}' % val
        rp = self.inproc(self.write("d.png", B.make_png(B.t_text("settings", body))))
        self.assertEqual([x["sha256_prefix"] for x in self.prim(rp, "K2")], [scan.sha8(val)])

    def test_trivial_values_and_prose_are_not_findings(self):
        body = B.jdump({"api_key": "", "token": "none", "password": "false", "secret": "your_api_key",
                        "apikey": "<paste key here>", "bearer": "${TOKEN}", "client_secret": "xxxxxxxx",
                        "max_tokens": 77, "token_normalization": "length+mean", "tokenizer": "default-clip",
                        "note": "the secret token to a happy life is a good password manager"})
        rp = self.inproc(self.write("t.png", B.make_png(B.t_text("settings", body))))
        self.assertEqual(rp.findings, [])
        self.assertEqual(self.code_of(rp), 0)

    def test_truncated_json_still_yields_named_secret(self):
        val = self.fake.secret_value()
        body = '{"a": {"password": "%s", "b": ["unterminated' % val
        rp = self.inproc(self.write("t.png", B.make_png(B.t_text("settings", body))))
        self.assertEqual([x["sha256_prefix"] for x in self.prim(rp, "K2")], [scan.sha8(val)])

    def test_assignment_in_plain_text(self):
        val = self.fake.secret_value()
        rp = self.inproc(self.write("t.png", self.png_prompt(self.note(4, "export MY_API_KEY=" + val + " # done"))))
        self.assertEqual([x["sha256_prefix"] for x in self.prim(rp, "K2")], [scan.sha8(val)])


class TestK3(ScanCase, Helpers):
    def test_webhooks(self):
        for name in ("discord_webhook", "slack_webhook"):
            url = getattr(self.fake, name)()
            rp = self.inproc(self.write(name + ".png", self.png_prompt(self.note(9, "post to " + url + " now"))))
            h = self.prim(rp, "K3")
            self.assertEqual(len(h), 1, name)
            self.assertEqual(h[0]["sha256_prefix"], scan.sha8(url))
            self.assertEqual(h[0]["length"], len(url))

    def test_incomplete_webhook_is_not_flagged(self):
        rp = self.inproc(self.write("w.png", self.png_prompt(self.note(9, "see https://discord.com/api/webhooks/docs"))))
        self.assertEqual(self.prim(rp, "K3"), [])


class TestP(ScanCase, Helpers):
    def check(self, text, cls, expect_value=None, present=True):
        rp = self.inproc(self.write("p.png", self.png_prompt(self.note(2, text))))
        got = [x for x in self.prim(rp, cls)]
        if present:
            self.assertTrue(got, (cls, text))
            if expect_value is not None:
                self.assertEqual(got[0]["sha256_prefix"], scan.sha8(expect_value))
                self.assertEqual(got[0]["length"], len(expect_value))
        else:
            self.assertEqual(got, [], (cls, text))
        return rp

    def test_p1_home_paths(self):
        u = B.PERSONAS
        self.check("C:\\Users\\%s\\ComfyUI\\output\\a.png" % u["win_user"], "P1", u["win_user"])
        self.check("D:/Users/%s/Documents/x" % u["win_user"], "P1", u["win_user"])
        self.check("/home/%s/work/a.png" % u["posix_user"], "P1", u["posix_user"])
        self.check("/Users/%s/Library/x" % u["mac_user"], "P1", u["mac_user"])
        self.check("/mnt/c/Users/%s/Desktop" % u["win_user"], "P1", u["win_user"])
        self.check("file:///home/%s/a.png" % u["posix_user"], "P1", u["posix_user"])

    def test_p1_json_escaped_backslashes(self):
        u = B.PERSONAS["win_user"]
        body = B.jdump({"path": "C:\\Users\\%s\\ComfyUI\\x.png" % u})
        rp = self.inproc(self.write("e.png", B.make_png(B.t_text("settings", body))))
        self.assertEqual([x["sha256_prefix"] for x in self.prim(rp, "P1")], [scan.sha8(u)])

    def test_p1_placeholders_and_urls_are_clean(self):
        for t in ("C:\\Users\\Public\\Documents", "C:\\Users\\Default\\x", "C:\\Users\\All Users\\x", "/Users/Shared/x",
                  "C:\\Users\\<username>\\x", "C:\\Users\\%USERNAME%\\x", "/home/$USER/x", "https://site.io/home/page/z",
                  "/users/123/profile", "C:\\Users\\"):
            self.check(t, "P1", present=False)

    def test_p1_generic_names_are_still_reported(self):
        self.check("/home/user/x", "P1", "user")                 # may be a real account: reported on purpose
        self.check("C:\\Users\\Test Person\\Desktop", "P1", "Test Person")

    def test_p2_email(self):
        self.check("mail " + B.PERSONAS["email"] + " today", "P2", B.PERSONAS["email"])

    def test_p2_placeholders_are_clean(self):
        for t in ("user@example.com", "a.b@mail.example.org", "x@y.example", "me@host.test", "icon@2x.png",
                  "name@1.0.safetensors", "@handle and text"):
            self.check(t, "P2", present=False)

    def test_p3_private_ranges_and_internal_hosts(self):
        u = B.PERSONAS
        self.check("http://%s:8188/x" % u["ip_a"], "P3", u["ip_a"])
        self.check("ssh " + u["ip_b"], "P3", u["ip_b"])
        self.check("net " + u["ip_c"] + "/24", "P3", u["ip_c"])
        self.check("login " + u["host"], "P3", u["host"])
        self.check("nas.studio.lan share", "P3", "nas.studio.lan")
        self.check("gpu01.corp.internal", "P3", "gpu01.corp.internal")

    def test_p3_clean_controls(self):
        for t in ("version 1.2.3.4 build", "v10.1.2.3", "8.8.8.8", "172.32.0.1", "127.0.0.1", "10.0.19045.1",
                  "192.169.0.1", "see local.png and the lan party", "10.1.2.3.4"):
            self.check(t, "P3", present=False)


class TestG1(ScanCase):
    def test_exif_gps_both_byte_orders(self):
        for order in ("II", "MM"):
            tiff = B.exif_gps_tiff(order)
            rp = self.inproc(self.write("g%s.jpg" % order, B.make_jpeg(app1=[b"Exif\x00\x00" + tiff])))
            h = self.prim(rp, "G1")
            self.assertEqual(len(h), 1, order)
            self.assertEqual(h[0]["carrier"], "jpeg:exif")
            self.assertEqual(h[0]["length"], 48)
            self.assertEqual(self.code_of(rp), 1)

    def test_gps_ifd_that_is_also_named_as_the_exif_ifd(self):
        tiff = B.exif_gps_tiff("II", dup_exif_pointer=True)
        rp = self.inproc(self.write("d.jpg", B.make_jpeg(app1=[b"Exif\x00\x00" + tiff])))
        self.assertEqual(len(self.prim(rp, "G1")), 1)

    def test_zero_gps_is_not_a_finding(self):
        tiff = B.exif_gps_tiff("II", lat=((0, 1), (0, 1), (0, 1)), lon=((0, 1), (0, 1), (0, 1)))
        rp = self.inproc(self.write("z.jpg", B.make_jpeg(app1=[b"Exif\x00\x00" + tiff])))
        self.assertEqual(rp.findings, [])
        self.assertEqual(self.code_of(rp), 0)

    def test_forged_gps_count_is_unscannable_not_clean(self):
        tiff = B.exif_gps_tiff("II", forged_count=500000)
        rp = self.inproc(self.write("f.jpg", B.make_jpeg(app1=[b"Exif\x00\x00" + tiff])))
        self.assertEqual(rp.findings, [])
        self.assertIn("exif_malformed", [e["code"] for e in rp.errors])
        self.assertEqual(self.code_of(rp), 3)

    def test_xmp_gps(self):
        rp = self.inproc(self.write("x.jpg", B.make_jpeg(app1=[B.xmp_packet("12,34.5600N", "156,47.4000W")])))
        self.assertEqual(len(self.prim(rp, "G1")), 2)

    def test_gps_in_png_exif_chunk(self):
        rp = self.inproc(self.write("e.png", B.make_png(B.chunk("eXIf", B.exif_gps_tiff("MM")))))
        self.assertEqual(len(self.prim(rp, "G1")), 1)

    def test_gps_in_png_raw_profile_text_chunk(self):
        tiff = B.exif_gps_tiff("II")
        body = "\nexif\n%8d\n%s\n" % (len(tiff) + 6, (b"Exif\x00\x00" + tiff).hex())
        rp = self.inproc(self.write("r.png", B.make_png(B.t_text("Raw profile type exif", body))))
        self.assertEqual(len(self.prim(rp, "G1")), 1)

    def test_exif_text_tag_secret(self):
        tok = self.fake.github_classic()
        rp = self.inproc(self.write("t.jpg", B.make_jpeg(app1=[b"Exif\x00\x00" + B.exif_text_tiff("shot with " + tok)])))
        self.assertEqual(len(self.prim(rp, "K1")), 1)

    def test_jpeg_comment_secret_and_trailing_data(self):
        tok = self.fake.anthropic()
        other = self.fake.hf()
        rp = self.inproc(self.write("c.jpg", B.make_jpeg(com=["note " + tok], tail=b"\x00\x00appended " + other.encode())))
        self.assertEqual(len(self.prim(rp, "K1")), 2)
        carriers = set(x["carrier"] for x in self.prim(rp, "K1"))
        self.assertEqual(carriers, {"jpeg:com", "jpeg:trailing"})


class TestH(ScanCase, Helpers):
    def test_h1_bypassed_and_muted_nodes(self):
        f = self.fake
        toks = {4: f.openai_legacy(), 2: f.anthropic(), 0: f.github_classic()}
        nodes = [B.ui_node(10 + m, "Note", ["token " + t], mode=m) for m, t in toks.items()]
        rp = self.inproc(self.write("h1.png", self.png_workflow(nodes)))
        by_id = {x["node_id"]: x for x in self.prim(rp, "K1")}
        self.assertEqual(set(by_id), {"14", "12", "10"})
        self.assertTrue(by_id["14"]["bypassed"])
        self.assertTrue(by_id["12"]["bypassed"])
        self.assertFalse(by_id["10"]["bypassed"])
        h1 = {x["node_id"] for x in self.comp(rp, "H1")}
        self.assertEqual(h1, {"14", "12"})
        self.assertTrue(all(x["bypassed"] for x in self.comp(rp, "H1")))

    def test_h1_with_named_secret_field(self):
        pw = self.fake.secret_value()
        rp = self.inproc(self.write("h1k2.png", self.png_workflow([B.ui_node(3, "L", [pw], names=["password"], mode=4)])))
        self.assertEqual(len(self.prim(rp, "K2")), 1)
        self.assertTrue(self.prim(rp, "K2")[0]["bypassed"])
        self.assertEqual(len(self.comp(rp, "H1")), 1)

    def test_h2_double_encoded(self):
        pw = self.fake.secret_value()
        inner = B.jdump({"auth": {"api_key": pw}})
        once = self.png_prompt({"8": B.api_node("Http", {"payload": inner})})
        rp = self.inproc(self.write("h2a.png", once))
        self.assertEqual([x["sha256_prefix"] for x in self.prim(rp, "K2")], [scan.sha8(pw)])
        self.assertEqual(len(self.comp(rp, "H2")), 1)
        twice = self.png_prompt({"8": B.api_node("Http", {"payload": B.jdump({"x": inner})})})
        rp = self.inproc(self.write("h2b.png", twice))
        self.assertEqual(len(self.prim(rp, "K2")), 1)
        self.assertEqual(len(self.comp(rp, "H2")), 1)

    def test_h2_vendor_key_inside_json_string(self):
        tok = self.fake.slack_bot()
        rp = self.inproc(self.write("h2c.png", self.png_prompt({"8": B.api_node("Http", {"p": B.jdump([tok])})})))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertEqual(len(self.comp(rp, "H2")), 1)

    def test_plain_not_double_encoded(self):
        rp = self.inproc(self.write("p.png", self.png_prompt(self.note(1, self.fake.google()))))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertEqual(self.comp(rp, "H2"), [])
        self.assertEqual(self.comp(rp, "H1"), [])

    def test_h3_compressed_chunks(self):
        tok = self.fake.openai_legacy()
        body = B.jdump(B.api_prompt(self.note(5, "k " + tok)))
        for name, chunk in (("z", B.z_text("prompt", body)), ("i", B.i_text("prompt", body, compressed=True))):
            rp = self.inproc(self.write(name + ".png", B.make_png(chunk)))
            self.assertEqual(len(self.prim(rp, "K1")), 1, name)
            self.assertEqual(len(self.comp(rp, "H3")), 1, name)
            self.assertEqual(self.prim(rp, "K1")[0]["carrier"], "png:" + ("zTXt" if name == "z" else "iTXt"))

    def test_uncompressed_chunks_are_not_h3(self):
        tok = self.fake.openai_legacy()
        body = B.jdump(B.api_prompt(self.note(5, "k " + tok)))
        for name, chunk in (("t", B.t_text("prompt", body)), ("i", B.i_text("prompt", body, compressed=False))):
            rp = self.inproc(self.write(name + ".png", B.make_png(chunk)))
            self.assertEqual(len(self.prim(rp, "K1")), 1, name)
            self.assertEqual(self.comp(rp, "H3"), [], name)


class TestM1(ScanCase, Helpers):
    def wf(self):
        return B.jdump(B.api_prompt())

    def test_workflow_json_in_ilst_tag(self):
        rp = self.inproc(self.write("a.mp4", B.make_mp4(meta=B.meta_ilst([B.ilst_item(b"\xa9cmt", self.wf())]))))
        m = self.prim(rp, "M1")
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0]["carrier"], "mp4:tag")
        self.assertEqual(self.code_of(rp), 1)

    def test_workflow_json_in_quicktime_udta_atom(self):
        rp = self.inproc(self.write("q.mov", B.make_mp4(udta_children=[B.qt_text_atom(b"\xa9cmt", self.wf())])))
        self.assertEqual(len(self.prim(rp, "M1")), 1)

    def test_workflow_json_in_mdta_key(self):
        ui = B.jdump(B.ui_workflow([B.ui_node(1, "Note", ["x"])]))
        rp = self.inproc(self.write("m.mp4", B.make_mp4(meta=B.meta_mdta([("prompt", self.wf()), ("workflow", ui)]))))
        self.assertEqual(len(self.prim(rp, "M1")), 2)

    def test_secret_inside_tag_json(self):
        tok = self.fake.openai_legacy()
        wf = B.jdump(B.api_prompt({"20": B.api_node("Note", {"text": tok})}))
        rp = self.inproc(self.write("s.mp4", B.make_mp4(meta=B.meta_ilst([B.ilst_item(b"desc", wf)]))))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertEqual(self.prim(rp, "K1")[0]["node_id"], "20")
        self.assertEqual(len(self.prim(rp, "M1")), 1)

    def test_hidden_boxes_ffprobe_cannot_see(self):
        tok = self.fake.hf()
        payload = ("junk " + tok + " tail").encode()
        for typ in (b"free", b"skip", b"uuid", b"zzzz"):
            body = (b"\x11" * 16 + payload) if typ == b"uuid" else payload
            rp = self.inproc(self.write(typ.decode() + ".mp4", B.make_mp4(appended=[B.box(typ, body)])))
            m = self.prim(rp, "M1")
            self.assertEqual(len(m), 1, typ)
            # registered codes print as themselves; an unknown code ("zzzz") prints as box~<hash>, so a file
            # cannot spell a message with its box types
            self.assertEqual(m[0]["carrier"], "mp4:box:" + scan.safe_box_type(typ), typ)
            if typ == b"zzzz":
                self.assertRegex(m[0]["carrier"], r"^mp4:box:box~[0-9a-f]{8}$")
            else:
                self.assertEqual(m[0]["carrier"], "mp4:box:" + typ.decode(), typ)
            self.assertEqual(len(self.prim(rp, "K1")), 1, typ)

    def test_binary_hidden_box(self):
        blob = bytes((i * 37 + 11) % 256 for i in range(300))
        rp = self.inproc(self.write("b.mp4", B.make_mp4(appended=[B.box(b"free", blob)])))
        self.assertEqual(len(self.prim(rp, "M1")), 1)

    def test_clean_controls(self):
        clean = B.make_mp4(meta=B.meta_ilst([B.ilst_item(b"\xa9too", "Lavf60.16.100"),
                                              B.ilst_item(b"\xa9nam", "A short film")]),
                           appended=[B.box(b"free", b"\x00" * 64)], ffmpeg_like_free=True)
        rp = self.inproc(self.write("c.mp4", clean))
        self.assertEqual(rp.findings, [])
        self.assertEqual(self.code_of(rp), 0)

    def test_xmp_uuid_box_is_scanned_not_flagged_as_hidden(self):
        xmp = (b"<x:xmpmeta>" + ("C:\\Users\\%s\\Videos\\a.prproj" % B.PERSONAS["win_user"]).encode() + b"</x:xmpmeta>")
        rp = self.inproc(self.write("x.mp4", B.make_mp4(appended=[B.box(b"uuid", scan._XMP_UUID + xmp)])))
        self.assertEqual(self.prim(rp, "M1"), [])
        self.assertEqual(len(self.prim(rp, "P1")), 1)

    def test_iso6709_location_tag(self):
        rp = self.inproc(self.write("l.mov", B.make_mp4(meta=B.meta_mdta([("com.apple.quicktime.location.ISO6709",
                                                                          "+12.3456-156.7890/")]))))
        self.assertEqual(len(self.prim(rp, "G1")), 1)

    @unittest.skipUnless(scan.find_program("ffmpeg") and scan.find_program("ffprobe"), "ffmpeg/ffprobe not on PATH")
    def test_real_ffmpeg_file_with_workflow_tag(self):
        import subprocess
        out = self.dir + "/real.mp4"
        r = subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i", "color=c=gray:s=64x64:d=0.4:r=5",
                            "-metadata", "comment=" + B.jdump(B.api_prompt({"30": B.api_node("N", {"text": self.fake.hf()})})),
                            "-pix_fmt", "yuv420p", out], capture_output=True)
        if r.returncode != 0:
            self.skipTest("ffmpeg could not make a clip")
        for use in (False, True):
            rp = self.inproc(out, ffprobe=use)
            self.assertEqual(len(self.prim(rp, "M1")), 1, use)
            self.assertEqual(len(self.prim(rp, "K1")), 1, use)
        clean = self.dir + "/clean.mp4"
        subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i", "color=c=gray:s=64x64:d=0.4:r=5",
                        "-pix_fmt", "yuv420p", clean], capture_output=True)
        rp = self.inproc(clean, ffprobe=True)
        self.assertEqual(rp.findings, [])
        self.assertEqual(self.code_of(rp), 0)


    @unittest.skipUnless(scan.find_program("ffmpeg") and scan.find_program("ffprobe"), "ffmpeg/ffprobe not on PATH")
    def test_box_walker_sees_everything_ffprobe_sees_in_real_files(self):
        import subprocess
        wf = B.jdump(B.api_prompt({"30": B.api_node("N", {"text": "hello"})}))
        checked = 0
        for container in ("mp4", "mov"):
            for flags in ([], ["-movflags", "use_metadata_tags"]):
                for key in ("comment", "description", "title", "prompt", "workflow", "artist", "copyright"):
                    out = "%s/%s_%s_%d.%s" % (self.dir, container, key, len(flags), container)
                    r = subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i",
                                        "color=c=gray:s=64x64:d=0.2:r=5", "-metadata", key + "=" + wf] + flags +
                                       ["-pix_fmt", "yuv420p", out], capture_output=True)
                    if r.returncode != 0:
                        continue
                    pr = subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format",
                                         "-show_streams", out], capture_output=True)
                    if b"class_type" not in pr.stdout:
                        continue
                    checked += 1
                    rp = self.inproc(out, ffprobe=False)            # the pure-python walker alone
                    self.assertEqual(len(self.prim(rp, "M1")), 1, (container, key, flags))
        self.assertGreaterEqual(checked, 8)


class TestCleanControls(ScanCase, Helpers):
    def test_clean_png_with_all_the_look_alikes(self):
        f = self.fake
        blob = f.pick(B.ALNUM + "+/", 20000) + "=="
        extra = {
            "20": B.api_node("Note", {"text": "a secret garden with a token of friendship; keep the secret. 1.2.3.4"}),
            "21": B.api_node("Loader", {"model_hash": f.pick(B.LOWHEX, 64), "uuid": f.uuid(), "seed": 18446744073709,
                                         "latent": blob, "contact": "docs@example.com", "title": "Load Checkpoint",
                                         "url": "https://example.com/a/b?c=d"}),
        }
        png = self.png_prompt(extra) + b""
        wf = B.make_png(B.t_text("prompt", B.jdump(B.api_prompt(extra))),
                        B.t_text("workflow", B.jdump(B.ui_workflow([B.ui_node(1, "Note", ["secret token prose"],
                                                                              title="Secret Token Notes")]))))
        for name, data in (("c1.png", png), ("c2.png", wf)):
            rp = self.inproc(self.write(name, data))
            self.assertEqual(rp.findings, [], name)
            self.assertEqual(rp.errors, [], name)
            self.assertEqual(self.code_of(rp), 0)
        self.assertIn("embedded_comfyui_api_json", [n["code"] for n in rp.info])

    def test_clean_jpeg_and_json_file(self):
        rp = self.inproc(self.write("c.jpg", B.make_jpeg(com=["a nice photo"])))
        self.assertEqual((rp.findings, rp.errors), ([], []))
        rp = self.inproc(self.write("w.json", B.jdump(B.ui_workflow([B.ui_node(1, "Note", ["hello"])])).encode()))
        self.assertEqual((rp.findings, rp.errors), ([], []))

    def test_json_file_carries_bypass_info(self):
        tok = self.fake.hf()
        wf = B.ui_workflow([B.ui_node(7, "Note", ["x " + tok], mode=4)])
        rp = self.inproc(self.write("w.json", B.jdump(wf).encode()))
        k = self.prim(rp, "K1")
        self.assertEqual((k[0]["node_id"], k[0]["bypassed"], k[0]["carrier"]), ("7", True, "json:file"))


if __name__ == "__main__":
    unittest.main()
