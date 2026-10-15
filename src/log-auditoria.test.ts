// log-auditoria.test.ts · Criado por FlowCore Soluções LTDA · flowcoresolucoes.com.br/codigos · licença MIT
import { describe, expect, it } from "vitest";
import { ArmazemAuditoriaMemoria, criarLogAuditoria, HASH_GENESE, jsonCanonico, verificarCadeia } from "./log-auditoria";

async function popular(chaveHmac?: string) {
  const armazem = new ArmazemAuditoriaMemoria();
  let t = Date.UTC(2026, 9, 15, 12, 0, 0);
  const log = criarLogAuditoria({ armazem, chaveHmac, now: () => (t += 1000) });
  await log.registrar({ ator: "u_1", acao: "usuario.login", dados: { ip: "10.0.0.1" } });
  await log.registrar({ ator: "u_1", acao: "pedido.criado", recurso: "pedido:1", dados: { valor: 24990 } });
  await log.registrar({ ator: "admin", acao: "pedido.cancelado", recurso: "pedido:1", dados: { motivo: "fraude" } });
  return { armazem, log };
}

describe("log-auditoria", () => {
  it("encadeia registros a partir do hash gênese", async () => {
    const { armazem } = await popular();
    const [a, b, c] = armazem.registros;
    expect(a).toMatchObject({ seq: 1, prevHash: HASH_GENESE, timestamp: "2026-10-15T12:00:01.000Z", recurso: null });
    expect(b.prevHash).toBe(a.hash);
    expect(c.prevHash).toBe(b.hash);
    expect(a.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verifica cadeia íntegra", async () => {
    const { armazem, log } = await popular();
    expect(await log.verificar()).toEqual({ valido: true, total: 3, ultimoHash: armazem.registros[2].hash });
  });

  it("hash do registro bate com SHA-256 calculado de forma independente", async () => {
    const { armazem } = await popular();
    const { hash, ...resto } = armazem.registros[0];
    const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(jsonCanonico(resto)));
    expect(Array.from(new Uint8Array(d), (x) => x.toString(16).padStart(2, "0")).join("")).toBe(hash);
  });

  it("detecta edição de dados", async () => {
    const { armazem, log } = await popular();
    armazem.registros[1].dados = { valor: 1 };
    expect(await log.verificar()).toEqual({ valido: false, seq: 2, motivo: "HASH_INVALIDO" });
  });

  it("detecta remoção no meio e reordenação", async () => {
    const { armazem } = await popular();
    const semMeio = [armazem.registros[0], armazem.registros[2]];
    expect(await verificarCadeia(semMeio)).toEqual({ valido: false, seq: 2, motivo: "SEQUENCIA_QUEBRADA" });
    const forjado = { ...armazem.registros[2], seq: 2 };
    expect(await verificarCadeia([armazem.registros[0], forjado])).toEqual({ valido: false, seq: 2, motivo: "ENCADEAMENTO_QUEBRADO" });
  });

  it("detecta remoção do fim usando âncora publicada", async () => {
    const { armazem } = await popular();
    const ancora = { seq: 3, hash: armazem.registros[2].hash };
    expect((await verificarCadeia(armazem.registros, { ancora })).valido).toBe(true);
    expect(await verificarCadeia(armazem.registros.slice(0, 2), { ancora })).toEqual({ valido: false, seq: 3, motivo: "ANCORA_NAO_CONFERE" });
  });

  it("com HMAC, a cadeia recalculada sem a chave não passa", async () => {
    const { armazem } = await popular("chave-secreta");
    expect((await verificarCadeia(armazem.registros, { chaveHmac: "chave-secreta" })).valido).toBe(true);
    expect(await verificarCadeia(armazem.registros)).toMatchObject({ valido: false, motivo: "HASH_INVALIDO" });
  });

  it("serializa gravações concorrentes sem quebrar a sequência", async () => {
    const armazem = new ArmazemAuditoriaMemoria();
    const log = criarLogAuditoria({ armazem });
    await Promise.all(Array.from({ length: 20 }, (_, i) => log.registrar({ ator: "job", acao: "item.processado", dados: { i } })));
    expect(armazem.registros.map((r) => r.seq)).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    expect((await log.verificar()).valido).toBe(true);
  });

  it("valida evento e protege contra seq duplicado no armazém", async () => {
    const log = criarLogAuditoria();
    await expect(log.registrar({ ator: "", acao: "x" })).rejects.toThrow("ator e acao");
    const armazem = new ArmazemAuditoriaMemoria();
    const r = { seq: 1, timestamp: "", ator: "a", acao: "b", recurso: null, dados: null, prevHash: HASH_GENESE, hash: "h" };
    await armazem.adicionar(r);
    await expect(armazem.adicionar(r)).rejects.toThrow("já existe");
    expect(jsonCanonico({ b: 1, a: [undefined, new Date(0)] })).toBe('{"a":[null,"1970-01-01T00:00:00.000Z"],"b":1}');
  });
});
