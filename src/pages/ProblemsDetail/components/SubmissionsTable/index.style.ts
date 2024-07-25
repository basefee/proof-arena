import { createStyles } from 'antd-style';

export const useStyles = createStyles(({ css }) => ({
  TableTitle: {
    color: 'rgba(43, 51, 45, .5)',
    fontSize: 14,
    fontWeight: 400,
    display: 'flex',
    flexDirection: 'column',
  },
  titleSpanStyle: {
    color: 'rgba(43, 51, 45, .5)',
    fontSize: 14,
    fontWeight: 400,
    transform: 'translateY(50%)',
  },
  submissionsTableBox: {
    border: '1px solid rgba(43, 51, 45, 0.05)',
    borderBottom: 'none',
    borderRadius: 16,
    overflow: 'hidden',
  },
  tableStyle: css(`
  .proof-table-thead{
    .proof-table-cell{
      padding: 12px;
    }
  }
  `),
  paginationStyle: { textAlign: 'center', marginTop: 24 },
}));