import {
  Action,
  ActionPanel,
  Detail,
  Form,
  Icon,
  getPreferenceValues,
  openExtensionPreferences,
  Toast,
  showToast,
} from "@raycast/api";
import { showFailureToast } from "@raycast/utils";
import { ReactNode, useCallback, useEffect, useState } from "react";
import {
  InvalidCredentialsError,
  InvalidMfaCodeError,
  PasswordRequiredError,
  signIn,
  signInWithPassword,
  submitMfa,
} from "./auth";

type Phase = "loading" | "mfa" | "password" | "ready" | "error";

interface ExtensionPreferences {
  appleId: string;
}

/**
 * Wraps a command so its content only renders once iCloud sign-in succeeds.
 * Handles the loading spinner, the password prompt (prompt mode), the 2FA code
 * prompt, and credential errors.
 */
export function AuthGate({ children }: { children: () => ReactNode }) {
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<Error | undefined>();

  const handleError = useCallback((err: Error) => {
    if (err instanceof PasswordRequiredError) {
      // Prompt mode: no cached session — ask for the password (never stored).
      setPhase("password");
      return;
    }
    setError(err);
    setPhase("error");
  }, []);

  const start = useCallback(async () => {
    setPhase("loading");
    setError(undefined);
    try {
      const result = await signIn();
      setPhase(result === "mfa" ? "mfa" : "ready");
    } catch (err) {
      handleError(err as Error);
    }
  }, [handleError]);

  useEffect(() => {
    start();
  }, [start]);

  const onSubmitPassword = useCallback(async (password: string) => {
    if (!password) {
      await showToast({
        style: Toast.Style.Failure,
        title: "Enter your password",
      });
      return;
    }
    const toast = await showToast({
      style: Toast.Style.Animated,
      title: "Signing in",
    });
    try {
      const result = await signInWithPassword(password);
      toast.style = Toast.Style.Success;
      toast.title = "Signed in";
      setPhase(result === "mfa" ? "mfa" : "ready");
    } catch (err) {
      toast.style = Toast.Style.Failure;
      toast.title = "Sign-in failed";
      handleError(err as Error);
    }
  }, []);

  const onSubmitCode = useCallback(async (code: string) => {
    const toast = await showToast({
      style: Toast.Style.Animated,
      title: "Verifying code",
    });
    try {
      await submitMfa(code);
      toast.style = Toast.Style.Success;
      toast.title = "Signed in";
      setPhase("ready");
    } catch (err) {
      if (err instanceof InvalidMfaCodeError) {
        toast.style = Toast.Style.Failure;
        toast.title = err.message;
        // stay on the MFA form to let them retry
      } else {
        await showFailureToast(err, { title: "Sign-in failed" });
        setError(err as Error);
        setPhase("error");
      }
    }
  }, []);

  if (phase === "ready") return <>{children()}</>;
  if (phase === "mfa") return <MfaForm onSubmit={onSubmitCode} />;
  if (phase === "password") return <PasswordForm onSubmit={onSubmitPassword} />;
  if (phase === "error") return <AuthError error={error} onRetry={start} />;
  return <Detail isLoading markdown="Signing in to iCloud…" />;
}

function PasswordForm({ onSubmit }: { onSubmit: (password: string) => void }) {
  const { appleId } = getPreferenceValues<ExtensionPreferences>();
  return (
    <Form
      navigationTitle="Apple ID Password"
      actions={
        <ActionPanel>
          <Action.SubmitForm
            title="Sign in"
            icon={Icon.Key}
            onSubmit={(values: { password: string }) =>
              onSubmit(values.password ?? "")
            }
          />
        </ActionPanel>
      }
    >
      <Form.Description
        text={`Enter the password for ${appleId || "your Apple ID"}. It is used for Apple's SRP sign-in, kept in memory only, and never written to disk. You'll be asked again only when the cached session (~1h) expires; the two-factor code is still only needed about once a month.`}
      />
      <Form.PasswordField id="password" title="Password" autoFocus />
    </Form>
  );
}

function MfaForm({ onSubmit }: { onSubmit: (code: string) => void }) {
  return (
    <Form
      navigationTitle="Two-Factor Authentication"
      actions={
        <ActionPanel>
          <Action.SubmitForm
            title="Verify"
            icon={Icon.Check}
            onSubmit={(values: { code: string }) =>
              onSubmit((values.code ?? "").replace(/\D/g, ""))
            }
          />
        </ActionPanel>
      }
    >
      <Form.Description text="Apple sent a 6-digit verification code to your trusted devices. Enter it below — this only happens about once a month." />
      <Form.TextField
        id="code"
        title="Verification Code"
        placeholder="123456"
        autoFocus
      />
    </Form>
  );
}

function AuthError({ error, onRetry }: { error?: Error; onRetry: () => void }) {
  const isCreds = error instanceof InvalidCredentialsError;
  const md = `# Could not sign in to iCloud\n\n${error?.message ?? "Unknown error."}${
    isCreds
      ? "\n\nCheck your Apple ID and password in the extension preferences."
      : ""
  }`;
  return (
    <Detail
      markdown={md}
      actions={
        <ActionPanel>
          <Action
            title="Open Extension Preferences"
            icon={Icon.Gear}
            onAction={openExtensionPreferences}
          />
          <Action
            title="Try Again"
            icon={Icon.ArrowClockwise}
            onAction={onRetry}
          />
        </ActionPanel>
      }
    />
  );
}
