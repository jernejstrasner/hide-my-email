import {
  Action,
  ActionPanel,
  Alert,
  Color,
  confirmAlert,
  Form,
  Icon,
  List,
  Toast,
  openExtensionPreferences,
  showToast,
  useNavigation,
} from "@raycast/api";
import { showFailureToast, useCachedPromise } from "@raycast/utils";
import {
  deactivateHme,
  deleteHme,
  HmeEmail,
  listHme,
  reactivateHme,
  updateHmeMetadata,
} from "./icloud";
import { CreateForm } from "./create";
import { AuthGate } from "./auth-gate";
import { signOut } from "./auth";
import { useState } from "react";

export default function SearchCommand() {
  return <AuthGate>{() => <SearchView />}</AuthGate>;
}

function SearchView() {
  const { data, isLoading, revalidate } = useCachedPromise(listHme, [], {
    keepPreviousData: true,
  });
  const [showInactive, setShowInactive] = useState(true);

  const emails = (data?.hmeEmails ?? [])
    .filter((e) => showInactive || e.isActive)
    .sort((a, b) => b.createTimestamp - a.createTimestamp);

  async function withToast(title: string, fn: () => Promise<void>) {
    const toast = await showToast({ style: Toast.Style.Animated, title });
    try {
      await fn();
      toast.style = Toast.Style.Success;
      toast.title = `${title} — done`;
      revalidate();
    } catch (err) {
      await showFailureToast(err, { title: `${title} failed` });
    }
  }

  return (
    <List
      isLoading={isLoading}
      searchBarPlaceholder="Search by address, label or note…"
      searchBarAccessory={
        <List.Dropdown
          tooltip="Filter"
          value={showInactive ? "all" : "active"}
          onChange={(v) => setShowInactive(v === "all")}
        >
          <List.Dropdown.Item title="All addresses" value="all" />
          <List.Dropdown.Item title="Active only" value="active" />
        </List.Dropdown>
      }
    >
      <List.EmptyView
        icon={Icon.Envelope}
        title={isLoading ? "Loading…" : "No Hide My Email addresses"}
        description="Press ⌘N to create your first one."
        actions={
          <ActionPanel>
            <Action.Push
              title="Create New Address"
              icon={Icon.Plus}
              target={<CreateForm onCreated={revalidate} />}
            />
          </ActionPanel>
        }
      />
      {emails.map((email) => (
        <List.Item
          key={email.anonymousId}
          icon={{
            source: email.isActive ? Icon.CheckCircle : Icon.XMarkCircle,
            tintColor: email.isActive ? Color.Green : Color.SecondaryText,
          }}
          title={email.label || email.hme}
          subtitle={email.label ? email.hme : undefined}
          keywords={[email.hme, email.label, email.note].filter(Boolean)}
          accessories={[
            { tag: email.forwardToEmail, icon: Icon.Forward },
            { date: new Date(email.createTimestamp) },
          ]}
          actions={
            <ActionPanel>
              <ActionPanel.Section>
                <Action.CopyToClipboard
                  title="Copy Email Address"
                  content={email.hme}
                  shortcut={{ modifiers: ["cmd"], key: "c" }}
                />
                <Action.Paste title="Paste Email Address" content={email.hme} />
                {email.note ? (
                  <Action.CopyToClipboard
                    title="Copy Note"
                    content={email.note}
                    shortcut={{ modifiers: ["cmd", "shift"], key: "c" }}
                  />
                ) : null}
              </ActionPanel.Section>

              <ActionPanel.Section>
                <Action.Push
                  title="Create New Address"
                  icon={Icon.Plus}
                  shortcut={{ modifiers: ["cmd"], key: "n" }}
                  target={<CreateForm onCreated={revalidate} />}
                />
                <Action.Push
                  title="Edit Label / Note"
                  icon={Icon.Pencil}
                  shortcut={{ modifiers: ["cmd"], key: "e" }}
                  target={<EditHme email={email} onSaved={revalidate} />}
                />
              </ActionPanel.Section>

              <ActionPanel.Section>
                {email.isActive ? (
                  <Action
                    title="Deactivate"
                    icon={Icon.XMarkCircle}
                    style={Action.Style.Destructive}
                    shortcut={{ modifiers: ["cmd"], key: "d" }}
                    onAction={() =>
                      withToast("Deactivating", () =>
                        deactivateHme(email.anonymousId),
                      )
                    }
                  />
                ) : (
                  <Action
                    title="Reactivate"
                    icon={Icon.CheckCircle}
                    shortcut={{ modifiers: ["cmd"], key: "r" }}
                    onAction={() =>
                      withToast("Reactivating", () =>
                        reactivateHme(email.anonymousId),
                      )
                    }
                  />
                )}
                <Action
                  title="Delete Permanently"
                  icon={Icon.Trash}
                  style={Action.Style.Destructive}
                  shortcut={{ modifiers: ["ctrl"], key: "x" }}
                  onAction={async () => {
                    if (email.isActive) {
                      await showToast({
                        style: Toast.Style.Failure,
                        title: "Deactivate it first",
                        message:
                          "iCloud only allows deleting inactive addresses.",
                      });
                      return;
                    }
                    const ok = await confirmAlert({
                      title: "Delete this address permanently?",
                      message: email.hme,
                      icon: Icon.Trash,
                      primaryAction: {
                        title: "Delete",
                        style: Alert.ActionStyle.Destructive,
                      },
                    });
                    if (ok) {
                      await withToast("Deleting", () =>
                        deleteHme(email.anonymousId),
                      );
                    }
                  }}
                />
              </ActionPanel.Section>

              <ActionPanel.Section>
                <Action
                  title="Refresh"
                  icon={Icon.ArrowClockwise}
                  shortcut={{ modifiers: ["cmd"], key: "r" }}
                  onAction={revalidate}
                />
                <Action
                  title="Open Extension Preferences"
                  icon={Icon.Gear}
                  onAction={openExtensionPreferences}
                />
                <Action
                  title="Sign out (Reset 2FA)"
                  icon={Icon.Logout}
                  style={Action.Style.Destructive}
                  onAction={async () => {
                    await signOut();
                    await showToast({
                      style: Toast.Style.Success,
                      title: "Signed out",
                      message: "Reopen the command to sign in again.",
                    });
                    revalidate();
                  }}
                />
              </ActionPanel.Section>
            </ActionPanel>
          }
        />
      ))}
    </List>
  );
}

function EditHme({ email, onSaved }: { email: HmeEmail; onSaved: () => void }) {
  const { pop } = useNavigation();

  async function submit(values: { label: string; note: string }) {
    const toast = await showToast({
      style: Toast.Style.Animated,
      title: "Saving",
    });
    try {
      await updateHmeMetadata(
        email.anonymousId,
        values.label.trim(),
        values.note,
      );
      toast.style = Toast.Style.Success;
      toast.title = "Saved";
      onSaved();
      pop();
    } catch (err) {
      await showFailureToast(err, { title: "Could not save" });
    }
  }

  return (
    <Form
      navigationTitle={`Edit ${email.hme}`}
      actions={
        <ActionPanel>
          <Action.SubmitForm title="Save" icon={Icon.Check} onSubmit={submit} />
        </ActionPanel>
      }
    >
      <Form.Description title="Address" text={email.hme} />
      <Form.Description title="Forwards To" text={email.forwardToEmail} />
      <Form.Separator />
      <Form.TextField id="label" title="Label" defaultValue={email.label} />
      <Form.TextArea id="note" title="Note" defaultValue={email.note} />
    </Form>
  );
}
