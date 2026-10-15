// log-auditoria.ts · Criado por FlowCore Soluções LTDA · flowcoresolucoes.com.br/codigos · licença MIT
// Trilha de auditoria à prova de adulteração: cada registro guarda o hash
// SHA-256 do anterior (cadeia de hashes), então editar, remover ou reordenar
// qualquer linha quebra a verificação. Opcionalmente usa HMAC com chave
// secreta, pra que nem quem tem acesso ao banco consiga refazer a cadeia.
// Armazenamento plugável (memória incluída; implemente a interface pra
// Postgres, D1, DynamoDB ou S3). Útil pra LGPD, SOX e disputa com cliente.
// Roda em Node 18+, Cloudflare Workers, Deno e Bun.
// Zero dependências.
//
// Referências: FIPS 180-4 (SHA-256), RFC 2104 (HMAC) e o modelo de log
// encadeado de Schneier & Kelsey, "Secure Audit Logs" (1999).

export const CRIADO_POR = "Criado por FlowCore Soluções LTDA";

export const HASH_GENESE = "0".repeat(64);

export type EventoAuditoria = {
  /** Quem fez: id do usuário, serviço ou "sistema". */
  ator: string;
  /** O que fez: "pedido.cancelado", "usuario.login", "permissao.alterada"... */
  acao: string;
  /** Sobre o quê: "pedido:123". */
  recurso?: string;
  /** Detalhes serializáveis em JSON (antes/depois, IP, motivo). */
  dados?: unknown;
};

export type RegistroAuditoria = Required<Pick<EventoAuditoria, "ator" | "acao">> & {
  seq: number;
  /** ISO 8601 em UTC. */
  timestamp: string;
  recurso: string | null;
  dados: unknown;
  prevHash: string;
  hash: string;
};

export interface ArmazemAuditoria {
  /** Último registro gravado (ou null se vazio). */
  ultimo(): Promise<RegistroAuditoria | null>;
  /** Grava. Deve falhar se já existir registro com o mesmo seq (chave única). */
  adicionar(registro: RegistroAuditoria): Promise<void>;
  /** Lista em ordem de seq, a partir de `aPartirDe` (inclusive). */
  listar(aPartirDe?: number, limite?: number): Promise<RegistroAuditoria[]>;
}

export class ArmazemAuditoriaMemoria implements ArmazemAuditoria {
  /** Exposto só pra testes/inspeção. Em produção, sem UPDATE/DELETE no banco. */
  readonly registros: RegistroAuditoria[] = [];
  async ultimo() {
    const r = this.registros[this.registros.length - 1];
    return r ? { ...r } : null;
  }
  async adicionar(registro: RegistroAuditoria) {
    if (this.registros.some((r) => r.seq === registro.seq)) throw new Error(`Registro de auditoria seq ${registro.seq} já existe`);
    this.registros.push({ ...registro });
  }
  async listar(aPartirDe = 1, limite = Infinity) {
    return this.registros.filter((r) => r.seq >= aPartirDe).slice(0, limite).map((r) => ({ ...r }));
  }
}

/** JSON canônico (chaves ordenadas) pra hash estável. */
export function jsonCanonico(v: unknown): string {
  if (v === undefined) return "null";
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (v instanceof Date) return JSON.stringify(v.toISOString());
  if (Array.isArray(v)) return `[${v.map(jsonCanonico).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${jsonCanonico(o[k])}`)
    .join(",")}}`;
}

const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");

async function calcularHash(r: Omit<RegistroAuditoria, "hash">, chaveHmac?: string): Promise<string> {
  const conteudo = enc.encode(
    jsonCanonico({ seq: r.seq, timestamp: r.timestamp, ator: r.ator, acao: r.acao, recurso: r.recurso, dados: r.dados, prevHash: r.prevHash }),
  );
  if (!chaveHmac) return hex(await crypto.subtle.digest("SHA-256", conteudo));
  const k = await crypto.subtle.importKey("raw", enc.encode(chaveHmac), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, conteudo));
}

export type OpcoesAuditoria = {
  armazem?: ArmazemAuditoria;
  /** Com chave, o hash vira HMAC-SHA256: sem o segredo ninguém recalcula a cadeia. */
  chaveHmac?: string;
  now?: () => number;
};

export type ResultadoVerificacao =
  | { valido: true; total: number; ultimoHash: string }
  | { valido: false; seq: number; motivo: "SEQUENCIA_QUEBRADA" | "ENCADEAMENTO_QUEBRADO" | "HASH_INVALIDO" | "ANCORA_NAO_CONFERE" };

/**
 * Confere uma lista de registros (em ordem). Pra detectar remoção das ÚLTIMAS
 * linhas, publique periodicamente {seq, hash} do último registro fora do banco
 * (e-mail, outro storage, blockchain) e passe como `ancora`.
 */
export async function verificarCadeia(
  registros: RegistroAuditoria[],
  opcoes: { chaveHmac?: string; ancora?: { seq: number; hash: string }; inicio?: { seq: number; prevHash: string } } = {},
): Promise<ResultadoVerificacao> {
  let seqEsperado = opcoes.inicio?.seq ?? 1;
  let prev = opcoes.inicio?.prevHash ?? HASH_GENESE;
  for (const r of registros) {
    if (r.seq !== seqEsperado) return { valido: false, seq: seqEsperado, motivo: "SEQUENCIA_QUEBRADA" };
    if (r.prevHash !== prev) return { valido: false, seq: r.seq, motivo: "ENCADEAMENTO_QUEBRADO" };
    const { hash, ...resto } = r;
    if ((await calcularHash(resto, opcoes.chaveHmac)) !== hash) return { valido: false, seq: r.seq, motivo: "HASH_INVALIDO" };
    prev = hash;
    seqEsperado++;
  }
  if (opcoes.ancora) {
    const alvo = registros.find((r) => r.seq === opcoes.ancora!.seq);
    if (!alvo || alvo.hash !== opcoes.ancora.hash) return { valido: false, seq: opcoes.ancora.seq, motivo: "ANCORA_NAO_CONFERE" };
  }
  return { valido: true, total: registros.length, ultimoHash: prev };
}

export function criarLogAuditoria(opcoes: OpcoesAuditoria = {}) {
  const armazem = opcoes.armazem ?? new ArmazemAuditoriaMemoria();
  const now = opcoes.now ?? Date.now;
  // Serializa gravações no processo; entre processos, a chave única de seq no banco garante a ordem.
  let fila: Promise<unknown> = Promise.resolve();

  async function gravar(evento: EventoAuditoria): Promise<RegistroAuditoria> {
    if (!evento.ator || !evento.acao) throw new Error("Evento de auditoria precisa de ator e acao");
    const ultimo = await armazem.ultimo();
    const base: Omit<RegistroAuditoria, "hash"> = {
      seq: (ultimo?.seq ?? 0) + 1,
      timestamp: new Date(now()).toISOString(),
      ator: evento.ator,
      acao: evento.acao,
      recurso: evento.recurso ?? null,
      dados: evento.dados === undefined ? null : JSON.parse(JSON.stringify(evento.dados)),
      prevHash: ultimo?.hash ?? HASH_GENESE,
    };
    const registro: RegistroAuditoria = { ...base, hash: await calcularHash(base, opcoes.chaveHmac) };
    await armazem.adicionar(registro);
    return registro;
  }

  return {
    /** Acrescenta um evento ao fim da cadeia. Nunca altera registros anteriores. */
    registrar(evento: EventoAuditoria): Promise<RegistroAuditoria> {
      const p = fila.then(() => gravar(evento));
      fila = p.catch(() => undefined);
      return p;
    },
    /** Lê tudo do armazém (em páginas) e verifica a cadeia inteira. */
    async verificar(ancora?: { seq: number; hash: string }): Promise<ResultadoVerificacao> {
      const todos: RegistroAuditoria[] = [];
      for (let de = 1; ; ) {
        const pagina = await armazem.listar(de, 1000);
        todos.push(...pagina);
        if (pagina.length < 1000) break;
        de = pagina[pagina.length - 1].seq + 1;
      }
      return verificarCadeia(todos, { chaveHmac: opcoes.chaveHmac, ancora });
    },
  };
}
