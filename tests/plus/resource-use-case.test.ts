/**
 * S2 batch 3 — `ResourceUseCase` unit tests.
 *
 * The use case is the only writer of `Resource` objects the Plus API exposes,
 * and it is the place where the three enumerations (`criticality`,
 * `environment`, `type`) are actually enforced — `Resource.create()` accepts
 * whatever it is handed, so this validation is the whole gate.
 *
 * The repository is an in-memory stub: no pg, no Docker, no network. What is
 * pinned here is the CONTRACT between the use case and its port — which port
 * method each public method reaches for, what it forwards, and what it does
 * with a miss — rather than the repository's own SQL (covered separately in
 * `postgres-resource-repository.test.ts`).
 */

import { ResourceUseCase } from "../../plus/application/use-cases/resource.use-case";
import type { IResourceRepository } from "../../plus/domain/repositories";
import { Resource } from "../../plus/domain/entities/resource";

/* ========================================================================== */
/* Instrumentation — the reason this file exists                               */
/* ========================================================================== */

describe("ResourceUseCase — instrumentation", () => {
  it("loads and instruments the module under test", () => {
    expect(typeof ResourceUseCase).toBe("function");
    expect(ResourceUseCase.name).toBe("ResourceUseCase");
  });
});

/* -------------------------------------------------------------------------- */
/* Stub repository                                                             */
/* -------------------------------------------------------------------------- */

type SearchArgs = Parameters<IResourceRepository["search"]>[0];

function makeRepository(): IResourceRepository & {
  calls: { method: string; args: unknown[] }[];
} {
  const calls: { method: string; args: unknown[] }[] = [];
  const record = (method: string, args: unknown[]) => {
    calls.push({ method, args });
  };
  const resource = Resource.create({
    id: "res-1",
    name: "Primary database",
    type: "database",
    endpoint: "db01.internal:5432",
    environment: "production",
    criticality: "critical",
  });

  return {
    calls,
    save: jest.fn(async (r: Resource) => {
      record("save", [r]);
      return r;
    }),
    findById: jest.fn(async () => resource),
    findByType: jest.fn(async () => [resource]),
    findByEnvironment: jest.fn(async () => [resource]),
    findByCriticality: jest.fn(async () => [resource]),
    findActive: jest.fn(async () => [resource]),
    search: jest.fn(async () => ({ resources: [resource], total: 1 })),
    delete: jest.fn(async () => true),
    list: jest.fn(async () => [resource]),
    isHealthy: jest.fn(async () => true),
    close: jest.fn(async () => undefined),
  } as unknown as IResourceRepository & {
    calls: { method: string; args: unknown[] }[];
  };
}

const VALID_INPUT = {
  id: "res-1",
  name: "Primary database",
  type: "database" as const,
  endpoint: "db01.internal:5432",
  environment: "production" as const,
  criticality: "critical" as const,
};

/* ========================================================================== */
/* create — the validation gate                                                */
/* ========================================================================== */

describe("ResourceUseCase.create", () => {
  it("rejects an unknown criticality BEFORE touching the repository", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    await expect(
      useCase.create({ ...VALID_INPUT, criticality: "catastrophic" as never }),
    ).rejects.toThrow("Invalid criticality: catastrophic");
    expect(repo.save).not.toHaveBeenCalled();
  });

  it("rejects an unknown environment", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    await expect(
      useCase.create({ ...VALID_INPUT, environment: "staging-eu" as never }),
    ).rejects.toThrow("Invalid environment: staging-eu");
    expect(repo.save).not.toHaveBeenCalled();
  });

  it("rejects an unknown resource type", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    await expect(
      useCase.create({ ...VALID_INPUT, type: "mainframe" as never }),
    ).rejects.toThrow("Invalid resource type: mainframe");
    expect(repo.save).not.toHaveBeenCalled();
  });

  it("accepts every value the enumerations declare", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    const criticalities = ["low", "medium", "high", "critical"] as const;
    const environments = [
      "production",
      "staging",
      "development",
      "testing",
      "dr",
    ] as const;
    const types = [
      "web",
      "ssh",
      "rdp",
      "vpn",
      "database",
      "kubernetes",
      "microservice",
      "firewall",
      "backup",
      "drp",
      "other",
    ] as const;

    for (const criticality of criticalities) {
      for (const environment of environments) {
        for (const type of types) {
          await useCase.create({
            ...VALID_INPUT,
            id: `res-${criticality}-${environment}-${type}`,
            criticality,
            environment,
            type,
          });
        }
      }
    }

    expect(repo.save).toHaveBeenCalledTimes(
      criticalities.length * environments.length * types.length,
    );
  });

  it("forwards the whole input to the repository", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    const saved = await useCase.create({
      ...VALID_INPUT,
      description: "Customer records",
      tags: ["pci"],
      ownerTeam: "platform",
      metadata: { cluster: "pg-16" },
    });

    expect(repo.save).toHaveBeenCalledTimes(1);
    const passed = (repo.save as jest.Mock).mock.calls[0][0] as Resource;
    expect(passed.id).toBe(VALID_INPUT.id);
    expect(passed.name).toBe(VALID_INPUT.name);
    expect(passed.type).toBe(VALID_INPUT.type);
    expect(passed.endpoint).toBe(VALID_INPUT.endpoint);
    expect(passed.environment).toBe(VALID_INPUT.environment);
    expect(passed.criticality).toBe(VALID_INPUT.criticality);
    expect(passed.description).toBe("Customer records");
    expect(passed.tags).toEqual(["pci"]);
    expect(passed.ownerTeam).toBe("platform");
    expect(passed.metadata).toEqual({ cluster: "pg-16" });
    expect(passed.active).toBe(true);
    expect(saved).toBe(passed);
  });
});

/* ========================================================================== */
/* Reads                                                                       */
/* ========================================================================== */

describe("ResourceUseCase — reads", () => {
  it("getById delegates to findById", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    const found = await useCase.getById("res-1");

    expect(repo.findById).toHaveBeenCalledWith("res-1");
    expect(found!.id).toBe("res-1");
  });

  it("list forwards the criteria and the total unchanged", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    const result = await useCase.list({ type: "database", limit: 5 });

    expect(repo.search).toHaveBeenCalledWith({ type: "database", limit: 5 });
    expect(result.total).toBe(1);
    expect(result.resources).toHaveLength(1);
  });

  it("list() with no argument still reaches search with an empty criteria", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    await useCase.list();

    expect(repo.search).toHaveBeenCalledWith({});
  });

  it("findByType / findByEnvironment / findByCriticality / findActive each hit their own port method", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    await useCase.findByType("web");
    await useCase.findByEnvironment("staging");
    await useCase.findByCriticality("low");
    await useCase.findActive();

    expect(repo.findByType).toHaveBeenCalledWith("web");
    expect(repo.findByEnvironment).toHaveBeenCalledWith("staging");
    expect(repo.findByCriticality).toHaveBeenCalledWith("low");
    expect(repo.findActive).toHaveBeenCalledTimes(1);
    expect(repo.list).not.toHaveBeenCalled();
    expect(repo.search).not.toHaveBeenCalled();
  });
});

/* ========================================================================== */
/* update                                                                      */
/* ========================================================================== */

describe("ResourceUseCase.update", () => {
  it("returns null and never writes when the id is unknown", async () => {
    const repo = makeRepository();
    (repo.findById as jest.Mock).mockResolvedValueOnce(null);
    const useCase = new ResourceUseCase(repo);

    await expect(useCase.update("ghost", { name: "Nope" })).resolves.toBeNull();
    expect(repo.save).not.toHaveBeenCalled();
  });

  it("applies every supported field and persists", async () => {
    const repo = makeRepository();
    const target = Resource.create({
      id: "res-1",
      name: "Old name",
      type: "database",
      endpoint: "db01.internal:5432",
      environment: "production",
      criticality: "critical",
      description: "old",
      tags: ["old"],
      ownerTeam: "team-a",
    });
    (repo.findById as jest.Mock).mockResolvedValueOnce(target);
    const useCase = new ResourceUseCase(repo);

    const updated = await useCase.update("res-1", {
      name: "New name",
      endpoint: "db02.internal:5432",
      environment: "staging",
      criticality: "high",
      description: "new",
      tags: ["pci", "tier-1"],
      ownerTeam: "team-b",
      metadata: { cluster: "pg-17" },
      active: false,
    });

    expect(updated!.name).toBe("New name");
    expect(updated!.endpoint).toBe("db02.internal:5432");
    expect(updated!.environment).toBe("staging");
    expect(updated!.criticality).toBe("high");
    expect(updated!.description).toBe("new");
    expect(updated!.tags).toEqual(["pci", "tier-1"]);
    expect(updated!.ownerTeam).toBe("team-b");
    expect(updated!.metadata).toEqual({ cluster: "pg-17" });
    expect(updated!.active).toBe(false);

    expect(repo.save).toHaveBeenCalledWith(target);
  });

  it("leaves a field alone when the patch omits it", async () => {
    const repo = makeRepository();
    const target = Resource.create({
      id: "res-1",
      name: "Old name",
      type: "database",
      endpoint: "db01.internal:5432",
      environment: "production",
      criticality: "critical",
      ownerTeam: "team-a",
      tags: ["keep"],
    });
    (repo.findById as jest.Mock).mockResolvedValueOnce(target);
    const useCase = new ResourceUseCase(repo);

    const updated = await useCase.update("res-1", { criticality: "low" });

    expect(updated!.criticality).toBe("low");
    expect(updated!.name).toBe("Old name");
    expect(updated!.endpoint).toBe("db01.internal:5432");
    expect(updated!.environment).toBe("production");
    expect(updated!.ownerTeam).toBe("team-a");
    expect(updated!.tags).toEqual(["keep"]);
  });

  it("copies the tags array instead of aliasing the caller's", async () => {
    const repo = makeRepository();
    const target = Resource.create({
      id: "res-1",
      name: "n",
      type: "web",
      endpoint: "https://example.com",
      environment: "production",
      criticality: "low",
    });
    (repo.findById as jest.Mock).mockResolvedValueOnce(target);
    const useCase = new ResourceUseCase(repo);

    const tags = ["pci"];
    await useCase.update("res-1", { tags });
    tags.push("mutated-after-the-fact");

    const passed = (repo.save as jest.Mock).mock.calls[0][0] as Resource;
    expect(passed.tags).toEqual(["pci"]);
  });

  it("merges metadata rather than replacing it", async () => {
    const repo = makeRepository();
    const target = Resource.create({
      id: "res-1",
      name: "n",
      type: "web",
      endpoint: "https://example.com",
      environment: "production",
      criticality: "low",
      metadata: { keep: true },
    });
    (repo.findById as jest.Mock).mockResolvedValueOnce(target);
    const useCase = new ResourceUseCase(repo);

    const updated = await useCase.update("res-1", { metadata: { added: 1 } });

    expect(updated!.metadata).toEqual({ keep: true, added: 1 });
  });
});

/* ========================================================================== */
/* delete                                                                      */
/* ========================================================================== */

describe("ResourceUseCase.delete", () => {
  it("returns the repository's verdict", async () => {
    const repo = makeRepository();
    const useCase = new ResourceUseCase(repo);

    await expect(useCase.delete("res-1")).resolves.toBe(true);

    (repo.delete as jest.Mock).mockResolvedValueOnce(false);
    await expect(useCase.delete("ghost")).resolves.toBe(false);
    expect(repo.delete).toHaveBeenCalledWith("ghost");
  });
});
