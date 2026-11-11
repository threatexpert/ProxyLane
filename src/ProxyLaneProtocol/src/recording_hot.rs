//! Bounded, write-through copies of metadata owned by the single recording writer.
//! Eviction discards only memory copies; every change is still committed to disk.
use std::{collections::BTreeMap,sync::Arc};
const BYTES:usize=8*1024*1024;
const ENTRIES:usize=256;
#[derive(Default)]
pub(crate) struct HotFiles {files:BTreeMap<String,(Arc<Vec<u8>>,u64)>,bytes:usize,clock:u64}
impl HotFiles {
    pub fn get(&mut self,key:&str)->Option<Arc<Vec<u8>>> {
        let item=self.files.get_mut(key)?;self.clock+=1;item.1=self.clock;Some(item.0.clone())
    }
    pub fn remove(&mut self,key:&str) {if let Some((data,_))=self.files.remove(key){self.bytes-=data.len();}}
    pub fn put(&mut self,key:&str,data:Arc<Vec<u8>>) {
        self.remove(key);
        // Headers/snapshots above this size remain disk-only; no unbounded hot entry.
        if data.len()>256*1024{return;}
        while self.files.len()>=ENTRIES || self.bytes+data.len()>BYTES {
            let oldest=self.files.iter().min_by_key(|(_,v)|v.1).map(|(k,_)|k.clone()).unwrap();self.remove(&oldest);
        }
        self.bytes+=data.len();self.clock+=1;self.files.insert(key.into(),(data,self.clock));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn bounds_and_replacement() {
        let mut hot=HotFiles::default();
        for n in 0..2000 {hot.put(&n.to_string(),Arc::new(vec![0;65536]));assert!(hot.bytes<=BYTES);assert!(hot.files.len()<=ENTRIES);}
        hot.put("1999",Arc::new(vec![1;3]));assert_eq!(hot.get("1999").unwrap().as_slice(),&[1;3]);
        hot.put("1999",Arc::new(vec![0;256*1024+1]));assert!(hot.get("1999").is_none());
    }
}
