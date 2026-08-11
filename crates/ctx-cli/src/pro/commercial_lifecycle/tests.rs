use std::io::Write as _;

use anyhow::anyhow;

use crate::ui::{ColorMode, RenderContext, StreamKind, TestContext};

use super::*;

fn stderr_context(width: usize) -> RenderContext {
    RenderContext::for_test(TestContext::tty(StreamKind::Stderr, width).color(ColorMode::Never))
}

fn styled_stderr_context(width: usize) -> RenderContext {
    RenderContext::for_test(TestContext::tty(StreamKind::Stderr, width).color(ColorMode::Always))
}

fn strip_ansi(rendered: &str) -> String {
    let mut stream = anstream::StripStream::new(Vec::new());
    stream.write_all(rendered.as_bytes()).unwrap();
    String::from_utf8(stream.into_inner()).unwrap()
}

fn line_fits_or_preserves_copyable_atom(line: &str, maximum: usize) -> bool {
    use unicode_width::UnicodeWidthStr as _;

    if line.width() <= maximum {
        return true;
    }
    if line.trim_start().starts_with("ctx ") {
        return true;
    }
    line.split_whitespace().any(|atom| {
        atom.contains("://") || atom.starts_with("--") || uuid::Uuid::parse_str(atom).is_ok()
    })
}

#[test]
fn paid_checkout_prompt_uses_the_fixed_monthly_price() {
    let context = stderr_context(80);
    assert_eq!(
        render_paid_checkout_prompt(&context, "https://checkout.stripe.test/session")
            .render_plain(),
        concat!(
            "Complete checkout to continue\n\n",
            "Product        $20/month\n",
            "Checkout link  https://checkout.stripe.test/session\n\n",
            "Hint: Complete the Stripe-hosted checkout.\n\n",
            "Next\n",
            "  https://checkout.stripe.test/session\n",
        )
    );
}

#[test]
fn live_sign_in_link_is_copyable_without_becoming_a_stale_terminal_recovery_action() {
    let context = stderr_context(80);
    let link = "https://auth.example.test/device";
    let rendered = render_device_sign_in(&context, link, "ABCD-EFGH").render_plain();
    assert!(rendered.contains(link), "{rendered}");
    assert_eq!(rendered.matches(link).count(), 1, "{rendered}");
    assert!(!rendered.contains("\nNext\n"), "{rendered}");
}

#[test]
fn terminal_sign_in_failure_supersedes_the_previous_link_with_ctx_pro() {
    for width in [32, 48, 80, 120] {
        let plain_context = stderr_context(width);
        let styled_context = styled_stderr_context(width);
        let link = "https://auth.example.test/device";
        let sign_in = render_device_sign_in(&plain_context, link, "ABCD-EFGH");
        let failure = super::super::human_actionable_error_document(
            &plain_context,
            &anyhow!("authentication_expired"),
            "ctx pro",
        )
        .unwrap();
        let rendered = format!("{}{}", sign_in.render_plain(), failure.render_plain());

        assert_eq!(rendered.matches(link).count(), 1, "{rendered}");
        assert!(
            !rendered.contains(&format!("Next\n  {link}\n")),
            "{rendered}"
        );
        assert_eq!(
            rendered.matches("Next\n  ctx pro\n").count(),
            1,
            "{rendered}"
        );
        let normalized = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            normalized.contains("sign-in link and code are no longer valid"),
            "{rendered}"
        );
        assert_eq!(
            strip_ansi(
                &render_device_sign_in(&styled_context, link, "ABCD-EFGH").render(&styled_context)
            ),
            sign_in.render_plain()
        );
        assert_eq!(
            strip_ansi(
                &super::super::human_actionable_error_document(
                    &styled_context,
                    &anyhow!("authentication_expired"),
                    "ctx pro",
                )
                .unwrap()
                .render(&styled_context)
            ),
            failure.render_plain()
        );
    }
}

#[test]
fn sign_in_service_unavailable_renders_recovery_without_an_authorization_link() {
    for width in [32, 48, 80, 120] {
        let plain_context = stderr_context(width);
        let styled_context = styled_stderr_context(width);
        let plain = super::super::human_actionable_error_document(
            &plain_context,
            &anyhow!("service_unavailable"),
            "ctx pro",
        )
        .unwrap()
        .render_plain();
        let styled = super::super::human_actionable_error_document(
            &styled_context,
            &anyhow!("service_unavailable"),
            "ctx pro",
        )
        .unwrap()
        .render(&styled_context);

        let normalized = plain.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            normalized.starts_with("✗ ctx Pro is temporarily unavailable"),
            "{plain}"
        );
        assert!(plain.contains("Next\n  ctx pro\n"), "{plain}");
        assert!(!plain.contains("Sign-in link"), "{plain}");
        assert!(!plain.contains("Code"), "{plain}");
        assert!(!plain.contains("service_unavailable"), "{plain}");
        assert_eq!(strip_ansi(&styled), plain);
    }
}

#[test]
fn terminal_trial_conversion_has_exact_human_copy() {
    assert_eq!(
        render_trial_conversion(&stderr_context(80)).render_plain(),
        "! The free Pro trial is unavailable for this device\n\
         Sign in to continue with paid Pro.\n"
    );
}

#[test]
fn sign_in_and_checkout_renderers_fit_supported_widths_and_sanitize_values() {
    for width in [32, 48, 80, 120] {
        let context = stderr_context(width);
        for document in [
            render_device_sign_in(
                &context,
                "https://auth.example.test/device?next=\u{1b}[2J",
                "ABCD-EFGH\nsecret",
            ),
            render_paid_checkout_prompt(
                &context,
                "https://checkout.stripe.test/session?next=\u{1b}[2J",
            ),
        ] {
            let rendered = document.render_plain();
            assert!(!rendered.contains('\u{1b}'));
            assert!(rendered.contains("\\x1b"));
            assert!(rendered.contains("\\n") || !rendered.contains("secret"));
            let maximum = context.content_width().unwrap_or(1);
            assert!(
                rendered
                    .lines()
                    .all(|line| line_fits_or_preserves_copyable_atom(line, maximum)),
                "{rendered:?}"
            );
        }
    }
}
