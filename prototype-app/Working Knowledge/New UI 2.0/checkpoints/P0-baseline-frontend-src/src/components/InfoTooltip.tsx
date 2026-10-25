type Props = {
  text: string;
};

export function InfoTooltip({ text }: Props) {
  return <span className="sn-tooltip" title={text} aria-label={text}>ⓘ</span>;
}
