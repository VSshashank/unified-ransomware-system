from datasets import load_dataset

# Stream just a tiny bit to inspect
dataset = load_dataset("cw1521/ember2018-malware", split="train", streaming=True)

print("--- DEBUGGING DATA STRUCTURE ---")
for i, sample in enumerate(dataset):
    label = sample['label']
    print(f"Row {i}: Label is '{label}' | Type is: {type(label)}")
    
    # Check the first 10 rows then stop
    if i >= 10:
        break