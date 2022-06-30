#include<vector>
std::vector<double_t> lagrange(std::vector<int> indices, int t_threshold, int val=0){
    // if(val!=0) cout << val << "val" << endl;
    std::vector<double_t> lagrange_(t_threshold);
    std::fill(lagrange_.begin(), lagrange_.end(), 1.0f);
    for(size_t i = 0; i < t_threshold; i++){
        int index = indices[i];
        for(size_t j = 0; j < t_threshold; j++){
            int index_j = indices[j];
            if(index!= index_j){
                lagrange_[i] *= static_cast<double_t>(val-index_j)/(float)(index-index_j);
            }
        }
    }
    return lagrange_;
}