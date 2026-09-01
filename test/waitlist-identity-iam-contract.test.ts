import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const bootstrapModule = join(root, "terraform/modules/bootstrap/main.tf");
const bootstrapDeployment = join(root, "terraform/deployments/bootstrap/main.tf");

// Extracts one HCL block by its resource header, up to the first line that
// closes at column zero. Enough for the flat resource blocks in this module,
// and it keeps the assertions below scoped to the block they name rather than
// matching a permission string anywhere in the file.
// Comments in these blocks name the permissions that are deliberately absent,
// so a contract test that searched raw text would match its own justification
// for excluding them. Assertions run against the stripped source.
function withoutComments(source: string): string {
  return source
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");
}

// Every permission literal actually granted by a block.
//
// Scoped to the `permissions` list so that service names appearing in the
// block's `count` gate -- identitytoolkit.googleapis.com, for instance -- are
// not mistaken for granted permissions.
function grantedPermissions(source: string): string[] {
  const stripped = withoutComments(source);
  const start = stripped.indexOf("permissions");
  expect(start, "block must declare permissions").toBeGreaterThanOrEqual(0);
  return [...stripped.slice(start).matchAll(/"([a-z][a-zA-Z]*\.[a-zA-Z.]+)"/g)]
    .map((match) => match[1]!)
    .filter((value) => !value.endsWith(".googleapis.com"));
}

function block(source: string, header: string): string {
  const start = source.indexOf(header);
  expect(start, `${header} must exist`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf("\n}\n", start);
  expect(end, `${header} must terminate`).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("waitlist ownership grants are exactly least privilege", () => {
  test("the runtime holds only mail, assessment, and quota-consumer permissions", async () => {
    const source = await readFile(bootstrapModule, "utf8");
    const role = block(
      source,
      'resource "google_project_iam_custom_role" "waitlist_challenge_sender"',
    );
    expect(grantedPermissions(role)).toEqual([
      "firebaseauth.users.sendEmail",
      "serviceusage.services.use",
      "recaptchaenterprise.assessments.create",
    ]);
  });

  // Each of these would turn "may send a verification email" into something
  // materially larger: reading the account directory, taking over an account,
  // or reading provider secrets.
  test("the sender cannot read, create, alter, or delete an account", async () => {
    const source = await readFile(bootstrapModule, "utf8");
    const role = block(
      source,
      'resource "google_project_iam_custom_role" "waitlist_challenge_sender"',
    );
    const granted = grantedPermissions(role);
    for (const forbidden of [
      "firebaseauth.users.create",
      "firebaseauth.users.delete",
      "firebaseauth.users.get",
      "firebaseauth.users.update",
      "firebaseauth.users.createSession",
      "firebaseauth.configs.getSecret",
      "firebaseauth.configs.get",
      "firebaseauth.configs.update",
      "recaptchaenterprise.assessments.annotate",
      "recaptchaenterprise.keys.create",
      "recaptchaenterprise.keys.delete",
      "recaptchaenterprise.keys.get",
      "recaptchaenterprise.keys.list",
      "recaptchaenterprise.keys.retrievelegacysecretkey",
      "recaptchaenterprise.keys.update",
    ]) {
      expect(granted).not.toContain(forbidden);
    }
  });

  test("no predefined Firebase Auth admin role is granted anywhere", async () => {
    for (const path of [bootstrapModule, bootstrapDeployment]) {
      // Stripped: the module explains in a comment which predefined role it
      // refuses and why, and that explanation must not fail its own test.
      const source = withoutComments(await readFile(path, "utf8"));
      expect(source).not.toContain("roles/firebaseauth.admin");
      expect(source).not.toContain("roles/identityplatform.admin");
      expect(source).not.toContain("roles/firebase.admin");
    }
  });

  test("the sender role exists only where Identity Platform is required", async () => {
    const source = await readFile(bootstrapModule, "utf8");
    for (const header of [
      'resource "google_project_iam_custom_role" "waitlist_challenge_sender"',
      'resource "google_project_iam_member" "runtime_waitlist_challenge_sender"',
    ]) {
      expect(block(source, header)).toContain(
        'contains(var.required_services, "identitytoolkit.googleapis.com") ? 1 : 0',
      );
    }
  });
});

describe("the protected apply identity gains only what TTL and config need", () => {
  test("Firestore field TTL adds update but never create or delete", async () => {
    const source = await readFile(bootstrapModule, "utf8");
    const role = block(
      source,
      'resource "google_project_iam_custom_role" "protected_terraform_apply"',
    );
    const granted = grantedPermissions(role);
    for (const permission of [
      "datastore.indexes.get",
      "datastore.indexes.list",
      "datastore.indexes.update",
    ]) {
      expect(granted).toContain(permission);
    }
    // A field is patched, never created or destroyed -- Terraform's destroy
    // path is also a patch back to defaults.
    expect(granted).not.toContain("datastore.indexes.create");
    expect(granted).not.toContain("datastore.indexes.delete");
  });

  test("TTL permissions are gated on the dedicated flag, not on Firestore itself", async () => {
    const source = await readFile(bootstrapModule, "utf8");
    const role = block(
      source,
      'resource "google_project_iam_custom_role" "protected_terraform_apply"',
    );
    const stripped = withoutComments(role);
    const ttl = stripped.slice(0, stripped.indexOf("datastore.indexes.get"));
    // The nearest preceding gate is the dedicated flag, not the Firestore
    // service check that guards the database permissions above it.
    expect(ttl.lastIndexOf("var.manage_firestore_field_ttl ?"))
      .toBeGreaterThan(ttl.lastIndexOf('contains(var.required_services, "firestore.googleapis.com")'));
  });

  test("Identity Platform grants cover configuration and never accounts or secrets", async () => {
    const source = await readFile(bootstrapModule, "utf8");
    const role = block(
      source,
      'resource "google_project_iam_custom_role" "protected_terraform_apply"',
    );
    const granted = grantedPermissions(role);
    for (const permission of [
      "firebaseauth.configs.create",
      "firebaseauth.configs.get",
      "firebaseauth.configs.update",
    ]) {
      expect(granted).toContain(permission);
    }
    // The apply identity writes sign-in configuration. It has no reason to read
    // provider secrets or touch a single account.
    expect(granted).not.toContain("firebaseauth.configs.getSecret");
    expect(granted.filter((value) => value.startsWith("firebaseauth.users."))).toEqual([]);
  });

  test("reCAPTCHA key management can create and update but never delete or retrieve a secret", async () => {
    const source = await readFile(bootstrapModule, "utf8");
    const role = block(
      source,
      'resource "google_project_iam_custom_role" "protected_terraform_apply"',
    );
    const granted = grantedPermissions(role);
    for (const permission of [
      "recaptchaenterprise.keys.create",
      "recaptchaenterprise.keys.get",
      "recaptchaenterprise.keys.update",
    ]) {
      expect(granted).toContain(permission);
    }
    for (const forbidden of [
      "recaptchaenterprise.keys.delete",
      "recaptchaenterprise.keys.list",
      "recaptchaenterprise.keys.retrievelegacysecretkey",
    ]) {
      expect(granted).not.toContain(forbidden);
    }
  });

  test("the convergence reader can read the score key but cannot mutate it", async () => {
    const source = await readFile(bootstrapModule, "utf8");
    const role = block(
      source,
      'resource "google_project_iam_custom_role" "terraform_convergence_reader"',
    );
    const granted = grantedPermissions(role);
    expect(granted).toContain("recaptchaenterprise.keys.get");
    expect(granted.filter((value) => value.startsWith("recaptchaenterprise.keys."))).toEqual([
      "recaptchaenterprise.keys.get",
    ]);
  });

  test("the production deployer can only get the Terraform-created key metadata", async () => {
    const source = await readFile(bootstrapModule, "utf8");
    const role = block(
      source,
      'resource "google_project_iam_custom_role" "waitlist_recaptcha_key_reader"',
    );
    expect(grantedPermissions(role)).toEqual(["recaptchaenterprise.keys.get"]);
    expect(role).toContain(
      'contains(var.required_services, "recaptchaenterprise.googleapis.com") ? 1 : 0',
    );

    const binding = block(
      source,
      'resource "google_project_iam_member" "prod_deploy_waitlist_recaptcha_key_reader"',
    );
    expect(binding).toContain(
      'contains(var.required_services, "recaptchaenterprise.googleapis.com") ? 1 : 0',
    );
    expect(binding).toContain(
      "role    = google_project_iam_custom_role.waitlist_recaptcha_key_reader[0].name",
    );
    expect(binding).toContain(
      'member  = "serviceAccount:${google_service_account.prod_deploy.email}"',
    );
  });
});

describe("only the application that needs them declares them", () => {
  test("Identity Platform, reCAPTCHA, and TTL are scoped to the Medlock deployment", async () => {
    const source = await readFile(bootstrapDeployment, "utf8");
    expect(source.match(/identitytoolkit\.googleapis\.com/g)?.length).toBe(1);
    expect(source.match(/recaptchaenterprise\.googleapis\.com/g)?.length).toBe(1);
    expect(source.match(/manage_firestore_field_ttl\s*=\s*true/g)?.length).toBe(1);
    // And it is the Medlock entry that carries them.
    const medlock = source.slice(source.indexOf('"1025243085" = {'));
    expect(medlock.indexOf("identitytoolkit.googleapis.com")).toBeGreaterThan(-1);
    expect(medlock.indexOf("recaptchaenterprise.googleapis.com")).toBeGreaterThan(-1);
    expect(medlock.indexOf("manage_firestore_field_ttl = true")).toBeGreaterThan(-1);
  });

  test("the flag defaults to off so a new application inherits nothing", async () => {
    const variables = await readFile(
      join(root, "terraform/modules/bootstrap/variables.tf"),
      "utf8",
    );
    const declaration = block(variables, 'variable "manage_firestore_field_ttl"');
    expect(declaration).toContain("default     = false");
  });

  test("the API is enabled through Terraform, never out of band", async () => {
    const source = await readFile(bootstrapDeployment, "utf8");
    // It appears inside required_services, which google_project_service
    // iterates; nothing else turns it on.
    const medlock = source.slice(source.indexOf('"1025243085" = {'));
    const services = medlock.slice(
      medlock.indexOf("required_services"),
      medlock.indexOf("manage_firestore_field_ttl"),
    );
    expect(services).toContain("identitytoolkit.googleapis.com");
    expect(services).toContain("recaptchaenterprise.googleapis.com");
  });
});

// The ownership flow is keyless by construction. An API key would be a public
// credential that can be lifted from a page and replayed against sendOobCode
// for arbitrary addresses.
describe("no Identity Platform API key is provisioned", () => {
  test("no API key resource exists in platform Terraform", async () => {
    for (const path of [bootstrapModule, bootstrapDeployment]) {
      const source = withoutComments(await readFile(path, "utf8"));
      expect(source).not.toContain("google_apikeys_key");
      expect(source).not.toContain("apikeys.googleapis.com");
    }
  });
});
