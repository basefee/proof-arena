export const problemsListData = {
  data: [
    {
      id: 1001,
      execution_number: 1002,
      problem_name: 'Keccak256 Hash',
      user_name: 'Polyhedra Network',
      user_avatar: 'https://stake.polyhedra.foundation/logo.png',
      create_time: 'Jul 15, 2024, 16:58:53 (UTC+08:00)',
    },
    {
      id: 1002,
      execution_number: 6732,
      problem_name: 'SHA256 Hash',
      user_name: 'Polyhedra Network',
      user_avatar: 'https://stake.polyhedra.foundation/logo.png',
      create_time: 'Jul 15, 2024, 18:58:53 (UTC+08:00)',
    },
    {
      id: 1003,
      execution_number: 3600,
      problem_name: 'ECDSA Signature',
      user_name: 'Polyhedra Network',
      user_avatar: 'https://stake.polyhedra.foundation/logo.png',
      create_time: 'Jul 15, 2024, 18:59:53 (UTC+08:00)',
    },
    {
      id: 1004,
      execution_number: 3600,
      problem_name: 'Poseidon2 Hash M31',
      user_name: 'Polyhedra Network',
      user_avatar: 'https://stake.polyhedra.foundation/logo.png',
      create_time: 'Jul 15, 2024, 18:59:53 (UTC+08:00)',
    },
    {
      id: 1005,
      execution_number: 3600,
      problem_name: 'Poseidon2 Hash BN254',
      user_name: 'Polyhedra Network',
      user_avatar: 'https://stake.polyhedra.foundation/logo.png',
      create_time: 'Jul 15, 2024, 18:59:53 (UTC+08:00)',
    },
  ],
  total: 5,
};

export const problemsDetailData = [
  {
    id: 1001,
    execution_number: 1002,
    problem_name: 'Keccak256 Hash',
    user_name: 'Polyhedra Network',
    user_avatar: 'https://stake.polyhedra.foundation/logo.png',
    create_time: 'Jul 15, 2024, 16:58:53 (UTC+08:00)',
    detail_link: '',
    desc: 'Test vectors <a href="https://emn178.github.io/online-tools/keccak_256.html">https://emn178.github.io/online-tools/keccak_256.html</a>',
    submissionsTableData: [
      {
        id: 1,
        prover_name: 'Alph,algo 1',
        proof_system: 'Alph',
        algorithm: 'algo 1',
        status: 'pending',
        setup_time: 3.5,
        witness_generation_time: 3.5,
        proof_generation_time: 3.5,
        verify_time: 3.5,
        peak_memory: 644,
        proof_size: 542,
      },
      {
        id: 2,
        prover_name: 'Alph,algo 2',
        proof_system: 'Alph',
        algorithm: 'algo 2',
        status: 'running',
        setup_time: 6.5,
        witness_generation_time: 3.5,
        proof_generation_time: 8.5,
        verify_time: 5.5,
        peak_memory: 1044,
        proof_size: 542,
      },
      {
        id: 3,
        prover_name: 'Alph,algo 3',
        proof_system: 'Alph',
        algorithm: 'algo 3',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 4,
        prover_name: 'Beta,algo 4',
        proof_system: 'Beta',
        algorithm: 'algo 1',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 5,
        prover_name: 'Beta,algo 5',
        proof_system: 'Beta',
        algorithm: 'algo 5',
        status: 'completed',
        setup_time: 16.5,
        witness_generation_time: 2.5,
        proof_generation_time: 6.5,
        verify_time: 7.5,
        peak_memory: 1404,
        proof_size: 202,
      },
    ],
  },
  {
    id: 1002,
    execution_number: 6732,
    problem_name: 'SHA256 Hash',
    user_name: 'Polyhedra Network',
    user_avatar: 'https://stake.polyhedra.foundation/logo.png',
    detail_link: '/problemsDescription/sha256_hash_details.md',
    create_time: 'Jul 15, 2024, 18:58:53 (UTC+08:00)',
    desc: 'Test vectors <a href="https://emn178.github.io/online-tools/sha256.html">https://emn178.github.io/online-tools/sha256.html</a>',
    submissionsTableData: [
      {
        id: 1,
        prover_name: 'Alph,algo 1',
        proof_system: 'Alph',
        algorithm: 'algo 1',
        status: 'pending',
        setup_time: 3.5,
        witness_generation_time: 3.5,
        proof_generation_time: 3.5,
        verify_time: 3.5,
        peak_memory: 644,
        proof_size: 542,
      },
      {
        id: 2,
        prover_name: 'Alph,algo 2',
        proof_system: 'Alph',
        algorithm: 'algo 2',
        status: 'running',
        setup_time: 6.5,
        witness_generation_time: 3.5,
        proof_generation_time: 8.5,
        verify_time: 5.5,
        peak_memory: 1044,
        proof_size: 542,
      },
      {
        id: 3,
        prover_name: 'Alph,algo 3',
        proof_system: 'Alph',
        algorithm: 'algo 3',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 4,
        prover_name: 'Beta,algo 4',
        proof_system: 'Beta',
        algorithm: 'algo 1',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 5,
        prover_name: 'Beta,algo 5',
        proof_system: 'Beta',
        algorithm: 'algo 5',
        status: 'completed',
        setup_time: 16.5,
        witness_generation_time: 2.5,
        proof_generation_time: 6.5,
        verify_time: 7.5,
        peak_memory: 1404,
        proof_size: 202,
      },
    ],
  },
  {
    id: 1003,
    execution_number: 3600,
    problem_name: 'ECDSA Signature',
    user_name: 'Polyhedra Network',
    user_avatar: 'https://stake.polyhedra.foundation/logo.png',
    create_time: 'Jul 15, 2024, 18:59:53 (UTC+08:00)',
    detail_link: '',
    desc: 'Test vectors <a href="https://emn178.github.io/online-tools/ecdsa_verify.html">https://emn178.github.io/online-tools/ecdsa_verify.html</a>',
    submissionsTableData: [
      {
        id: 1,
        prover_name: 'Alph,algo 1',
        proof_system: 'Alph',
        algorithm: 'algo 1',
        status: 'pending',
        setup_time: 3.5,
        witness_generation_time: 3.5,
        proof_generation_time: 3.5,
        verify_time: 3.5,
        peak_memory: 644,
        proof_size: 542,
      },
      {
        id: 2,
        prover_name: 'Alph,algo 2',
        proof_system: 'Alph',
        algorithm: 'algo 2',
        status: 'running',
        setup_time: 6.5,
        witness_generation_time: 3.5,
        proof_generation_time: 8.5,
        verify_time: 5.5,
        peak_memory: 1044,
        proof_size: 542,
      },
      {
        id: 3,
        prover_name: 'Alph,algo 3',
        proof_system: 'Alph',
        algorithm: 'algo 3',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 4,
        prover_name: 'Beta,algo 4',
        proof_system: 'Beta',
        algorithm: 'algo 1',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 5,
        prover_name: 'Beta,algo 5',
        proof_system: 'Beta',
        algorithm: 'algo 5',
        status: 'completed',
        setup_time: 16.5,
        witness_generation_time: 2.5,
        proof_generation_time: 6.5,
        verify_time: 7.5,
        peak_memory: 1404,
        proof_size: 202,
      },
    ],
  },
  {
    id: 1004,
    execution_number: 3600,
    problem_name: 'Poseidon2 Hash M31',
    user_name: 'Polyhedra Network',
    user_avatar: 'https://stake.polyhedra.foundation/logo.png',
    create_time: 'Jul 15, 2024, 18:59:53 (UTC+08:00)',
    detail_link: '',
    desc: '--',
    submissionsTableData: [
      {
        id: 1,
        prover_name: 'Alph,algo 1',
        proof_system: 'Alph',
        algorithm: 'algo 1',
        status: 'pending',
        setup_time: 3.5,
        witness_generation_time: 3.5,
        proof_generation_time: 3.5,
        verify_time: 3.5,
        peak_memory: 644,
        proof_size: 542,
      },
      {
        id: 2,
        prover_name: 'Alph,algo 2',
        proof_system: 'Alph',
        algorithm: 'algo 2',
        status: 'running',
        setup_time: 6.5,
        witness_generation_time: 3.5,
        proof_generation_time: 8.5,
        verify_time: 5.5,
        peak_memory: 1044,
        proof_size: 542,
      },
      {
        id: 3,
        prover_name: 'Alph,algo 3',
        proof_system: 'Alph',
        algorithm: 'algo 3',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 4,
        prover_name: 'Beta,algo 4',
        proof_system: 'Beta',
        algorithm: 'algo 1',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 5,
        prover_name: 'Beta,algo 5',
        proof_system: 'Beta',
        algorithm: 'algo 5',
        status: 'completed',
        setup_time: 16.5,
        witness_generation_time: 2.5,
        proof_generation_time: 6.5,
        verify_time: 7.5,
        peak_memory: 1404,
        proof_size: 202,
      },
    ],
  },
  {
    id: 1005,
    execution_number: 3600,
    problem_name: 'Poseidon2 Hash BN254',
    user_name: 'Polyhedra Network',
    detail_link: '',
    user_avatar: 'https://stake.polyhedra.foundation/logo.png',
    create_time: 'Jul 15, 2024, 18:59:53 (UTC+08:00)',
    desc: '--',
    submissionsTableData: [
      {
        id: 1,
        prover_name: 'Alph,algo 1',
        proof_system: 'Alph',
        algorithm: 'algo 1',
        status: 'pending',
        setup_time: 3.5,
        witness_generation_time: 3.5,
        proof_generation_time: 3.5,
        verify_time: 3.5,
        peak_memory: 644,
        proof_size: 542,
      },
      {
        id: 2,
        prover_name: 'Alph,algo 2',
        proof_system: 'Alph',
        algorithm: 'algo 2',
        status: 'running',
        setup_time: 6.5,
        witness_generation_time: 3.5,
        proof_generation_time: 8.5,
        verify_time: 5.5,
        peak_memory: 1044,
        proof_size: 542,
      },
      {
        id: 3,
        prover_name: 'Alph,algo 3',
        proof_system: 'Alph',
        algorithm: 'algo 3',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 4,
        prover_name: 'Beta,algo 4',
        proof_system: 'Beta',
        algorithm: 'algo 1',
        status: 'completed',
        setup_time: 12.5,
        witness_generation_time: 6.5,
        proof_generation_time: 10.5,
        verify_time: 3.5,
        peak_memory: 1644,
        proof_size: 202,
      },
      {
        id: 5,
        prover_name: 'Beta,algo 5',
        proof_system: 'Beta',
        algorithm: 'algo 5',
        status: 'completed',
        setup_time: 16.5,
        witness_generation_time: 2.5,
        proof_generation_time: 6.5,
        verify_time: 7.5,
        peak_memory: 1404,
        proof_size: 202,
      },
    ],
  },
];
