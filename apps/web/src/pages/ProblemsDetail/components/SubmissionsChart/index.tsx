import { ConfigProvider, Segmented } from 'antd';
import ReactEcharts from 'echarts-for-react';
import { useEffect, useState } from 'react';

import { useStyles } from './index.style.ts';

type SubmissionsChartType = {
  chartData: any[];
};

const createUnit = (type: string) => {
  switch (type) {
    case 'setup_time':
    case 'witness_generation_time':
    case 'proof_generation_time':
    case 'verify_time':
      return 'seconds';
    case 'peak_memory':
      return 'MB';
    case 'proof_size':
      return 'KB';
    default:
      return '';
  }
};
const segmentedOptions = [
  {
    label: 'Setup time',
    value: 'setup_time',
  },
  {
    label: 'Witness generation time',
    value: 'witness_generation_time',
  },
  {
    label: 'Proof generation time',
    value: 'proof_generation_time',
  },
  {
    label: 'Verification time',
    value: 'verify_time',
  },
  {
    label: 'Peak memory',
    value: 'peak_memory',
  },
  {
    label: 'Proof size',
    value: 'proof_size',
  },
];
const SubmissionsChart = ({ chartData }: SubmissionsChartType) => {
  const { styles } = useStyles();
  const [segmentedValue, setSegmentedValue] = useState<any>();
  const findChartName = (value: string) => {
    return segmentedOptions.find(item => item.value === value)?.label;
  };
  const options = {
    title: {
      subtext: `${findChartName(segmentedValue)}: ${createUnit(
        segmentedValue,
      )}`,
    },
    height: '86%',
    grid: {
      left: '1%',
      right: '1%',
      containLabel: true,
    },
    xAxis: {
      type: 'category',
      data: chartData?.map(item => item.prover_name),
    },
    yAxis: {
      type: 'value',
    },
    series: [
      {
        data: chartData?.map(item => item[segmentedValue]),
        type: 'bar',
        barWidth: 60,
        itemStyle: {
          color: '#EAEBEA',
          borderRadius: 4,
        },
        emphasis: {
          itemStyle: {
            color: '#34A853',
          },
          label: {
            show: true,
            position: 'top',
          },
        },
      },
    ],
  };
  useEffect(() => {
    setSegmentedValue(segmentedOptions[0].value);
  }, [chartData]);
  return (
    <div className={styles.submissionsChartBox}>
      <div className={styles.boxSpace}>
        <span className={styles.title}>Metric analysis charts</span>
        <ConfigProvider
          theme={{
            components: {
              Segmented: {
                itemColor: 'rgba(43, 51, 45, 0.60)',
                itemActiveBg: 'rgba(52, 168, 83, 0.10)',
                itemHoverBg: 'rgba(52, 168, 83, 0.10)',
                itemSelectedBg: 'rgba(52, 168, 83, 0.10)',
                itemSelectedColor: '#2B332D',
                trackBg: '#fff',
                borderRadius: 100,
              },
            },
          }}
        >
          <Segmented<string>
            className={styles.segmentedStyle}
            options={segmentedOptions}
            onChange={value => {
              setSegmentedValue(value);
            }}
            value={segmentedValue}
          />
        </ConfigProvider>
      </div>
      <ReactEcharts style={{ height: 470 }} option={options} />
    </div>
  );
};

export default SubmissionsChart;