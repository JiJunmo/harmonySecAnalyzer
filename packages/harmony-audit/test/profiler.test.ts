import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { profileProject, selectComponents } from "../src/project/profiler.js";

describe("Harmony project profiler", () => {
  it("derives deterministic entry candidates from module.json5", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-profile-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', type: 'entry', abilities: [{ name: 'MainAbility', srcEntry: './ets/MainAbility.ets', exported: true, skills: [{ actions: ['ohos.want.action.viewData'], uris: [{ scheme: 'demo' }] }] }] } }`);
    const model = await profileProject(root);
    expect(model.status).toBe("complete");
    expect(model.schema_version).toBe(2);
    expect(model.components).toHaveLength(1);
    expect(model.entry_candidates.map((row) => row.type)).toEqual(expect.arrayContaining(["component_scope", "exported_component", "deeplink", "implicit_want"]));
    expect(model.entry_candidates.map((row) => row.type)).toContain("common_event_candidate");
    expect(model.entry_candidates.filter((row) => row.type === "project_scope")).toHaveLength(1);
  });

  it("models declared HAP/HSP modules, products, permissions and local dependencies", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-profile-v2-"));
    await writeFile(join(root, "build-profile.json5"), `{ app: { products: [{name:'default'}, {name:'enterprise'}], buildModeSet: [{name:'debug'}, {name:'release'}] }, modules: [{name:'entry',srcPath:'./apps/entry',targets:[{name:'default',applyToProducts:['default','enterprise']}]},{name:'shared',srcPath:'./services/shared',targets:[{name:'default',applyToProducts:['enterprise']}]}] }`);
    for (const path of ["apps/entry", "services/shared", "unused"]) await mkdir(join(root, path, "src/main"), { recursive: true });
    await mkdir(join(root, "apps/entry/src/ohosTest"), { recursive: true });
    await writeFile(join(root, "apps/entry/src/main/module.json5"), `{module:{name:'entry',type:'entry',requestPermissions:[{name:'ohos.permission.INTERNET',usedScene:{abilities:['EntryAbility']}}],definePermissions:[{name:'com.demo.PRIVATE',grantMode:'system_grant'}],abilities:[{name:'EntryAbility',srcEntry:'./ets/EntryAbility.ets',exported:true}]}}`);
    await writeFile(join(root, "apps/entry/src/ohosTest/module.json5"), `{module:{name:'test',type:'feature',abilities:[{name:'TestAbility',exported:true}]}}`);
    await writeFile(join(root, "services/shared/src/main/module.json5"), `{module:{name:'shared',type:'shared',extensionAbilities:[{name:'SharedService',type:'service',srcEntry:'./ets/Service.ets',exported:true}]}}`);
    await writeFile(join(root, "unused/src/main/module.json5"), `{module:{name:'unused',type:'feature',abilities:[{name:'UnusedAbility'}]}}`);
    await writeFile(join(root, "apps/entry/oh-package.json5"), `{name:'entry',dependencies:{shared:'file:../../services/shared'}}`);
    await writeFile(join(root, "services/shared/oh-package.json5"), `{name:'shared',dependencies:{}}`);
    const model = await profileProject(root); const repeated = await profileProject(root);
    expect(model.status).toBe("complete"); expect(model.summary).toMatchObject({ modules: 2, discovered_modules: 3, requested_permissions: 1, defined_permissions: 1, module_dependencies: 1 });
    expect(model.build).toMatchObject({ scope: "declared_modules", product_scope: "union", products: ["default", "enterprise"], build_modes: ["debug", "release"] });
    expect(model.modules.filter((item) => item.included_in_build).map((item) => item.output_kind).sort()).toEqual(["hap", "hsp"]);
    expect(model.components.map((item) => item.name).sort()).toEqual(["EntryAbility", "SharedService"]);
    expect(model.entry_candidates.map((item) => item.type)).toContain("ipc_service_candidate");
    expect(model.module_dependencies).toHaveLength(1);
    expect(model.modules.map((item) => item.module_id)).toEqual(repeated.modules.map((item) => item.module_id));
  });
});

describe("component selection", () => {
  it("reports missing and ambiguous component selectors", () => {
    const model = { components: [{ component_id: "CMP-a", name: "Same" }, { component_id: "CMP-b", name: "Same" }] } as any;
    expect(() => selectComponents(model, ["missing"])).toThrow("component_not_found:missing");
    expect(() => selectComponents(model, ["Same"])).toThrow("component_ambiguous:Same:CMP-a,CMP-b");
    expect(selectComponents(model, ["CMP-a"])).toEqual(["CMP-a"]);
  });
});
