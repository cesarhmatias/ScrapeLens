// Transformações do corpo (Body.transformed). `chrome-decoded` é universal em
// respostas de texto (o CDP entrega o corpo já decodificado): vira só uma nota.
// Qualquer outra (charset:*, lossy-postData, desconhecidas) é aviso.

export interface TransformView {
  /** Transformações que tornam o corpo não idêntico ao fio de forma relevante. */
  warn: string[];
  /** true se havia `chrome-decoded`. */
  chromeDecoded: boolean;
}

export function classifyTransforms(transformed: string[] | undefined): TransformView {
  const list = transformed ?? [];
  return { warn: list.filter((item) => item !== "chrome-decoded"), chromeDecoded: list.includes("chrome-decoded") };
}
