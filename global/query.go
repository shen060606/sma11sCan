package global

// GenerateBatchID 生成批次ID
func GenerateBatchID() int {
	var maxID int
	row := DB.Model(&ScanTask{}).Select("batch_id").Where("batch_id IS NOT NULL").Order("batch_id desc").Limit(1).Row()

	if err := row.Scan(&maxID); err != nil {
		return 1
	}
	return maxID + 1
}

// GetAllTasks 查全表，前端自己分组
func GetAllTasks() ([]ScanTask, error) {
	var tasks []ScanTask
	err := DB.Where("batch_id != ''").Preload("Results").Order("batch_id desc, created_at desc").Find(&tasks).Error
	return tasks, err
}
