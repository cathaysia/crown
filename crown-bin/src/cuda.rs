use crate::args::HashAlgorithm;
use crown::cuda::mem::CudaMemory;

pub fn calc_and_output_hash(algorithm: HashAlgorithm, files: Vec<String>) {
    let mut all_data = Vec::new();
    let mut file_sizes = Vec::new();
    let mut file_offsets = Vec::new();
    let mut file_paths = Vec::new();

    let mut offset: u32 = 0;
    for path in &files {
        let content = std::fs::read(path).unwrap();
        file_sizes.push(content.len() as u32);
        all_data.extend_from_slice(&content);
        file_paths.push(path.clone());
        file_offsets.push(offset);
        offset += content.len() as u32;
    }

    let all_data = CudaMemory::from_slice_to_device(&all_data).unwrap();
    let file_sizes = CudaMemory::from_slice_to_device(&file_sizes).unwrap();
    let file_offsets = CudaMemory::from_slice_to_device(&file_offsets).unwrap();
    let output_size = match algorithm {
        HashAlgorithm::Md5Cuda => 16,
        HashAlgorithm::Sha256Cuda => 32,
        _ => unreachable!(),
    };
    let mut output = CudaMemory::<u8>::new_pined(output_size * file_paths.len()).unwrap();

    match algorithm {
        HashAlgorithm::Md5Cuda => {
            crown::md5::cuda::md5_sum_batch_cuda(
                &all_data,
                &file_sizes,
                &file_offsets,
                &mut output,
            )
            .unwrap();
        }
        HashAlgorithm::Sha256Cuda => {
            crown::sha256::cuda::sha256_sum_batch_cuda(
                &all_data,
                &file_sizes,
                &file_offsets,
                &mut output,
            )
            .unwrap();
        }
        _ => unreachable!(),
    }

    let output = output.to_vec().unwrap();
    for (i, path) in file_paths.iter().enumerate() {
        let hash_start = i * output_size;
        let hash_end = hash_start + output_size;
        let hash = &output[hash_start..hash_end];
        println!("{}  {}", hex::encode(hash), path);
    }
}
