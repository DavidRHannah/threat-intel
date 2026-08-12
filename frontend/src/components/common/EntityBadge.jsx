import { getEntityType } from '../../utils/formatters';

export function EntityBadge({ type }) {
  const entityInfo = getEntityType(type);
  
  return (
    <span className={`badge ${entityInfo.className}`}>
      {entityInfo.label}
    </span>
  );
}
