//! Recording-only overflow storage for HTTP exchanges. The configured pending
//! count is a resident working-set limit, never a reason to abandon parsing.
use crate::{cache::PayloadCache, Exchange};
use std::{collections::BTreeMap, fs};

#[derive(Default)]
pub(crate) struct Pending {
    memory:BTreeMap<u64,Exchange>,
    store:Option<(PayloadCache,String)>,
    limit:usize,
}
impl Pending {
    pub fn configure(&mut self,cache:Option<&PayloadCache>,limit:usize) {
        self.limit=limit;
        if self.store.is_none() {
            if let Some(c)=cache.filter(|c|c.is_recording()) {
                self.store=Some((c.clone(),format!("analysis/pending-{}",c.working_id())));
            }
        }
    }
    pub fn limited(&self)->bool {self.store.is_none() && self.memory.len()>=self.limit}
    fn path(&self,id:u64)->Option<std::path::PathBuf> {
        self.store.as_ref().map(|(c,dir)|c.directory().join(dir).join(format!("{id}.json")))
    }
    pub fn contains_key(&self,id:&u64)->bool {
        self.memory.contains_key(id)||self.path(*id).is_some_and(|p|fs::metadata(p).is_ok_and(|m|m.len()!=4))
    }
    fn room(&mut self)->Result<(),String> {
        if self.memory.len()<self.limit {return Ok(());}
        let Some((c,dir))=&self.store else {return Ok(());};
        let id=*self.memory.keys().next().unwrap();
        let e=&self.memory[&id];
        let value=serde_json::json!({"cache_id":e.cache.as_ref().map(|c|c.id()),"exchange":e});
        c.working_write(format!("{dir}/{id}.json"),serde_json::to_vec(&value).map_err(|e|e.to_string())?)?;
        self.memory.remove(&id);
        Ok(())
    }
    pub fn insert(&mut self,id:u64,e:Exchange)->Result<(),String> {
        self.room()?;self.memory.insert(id,e);Ok(())
    }
    fn load(&mut self,id:u64)->Result<(),String> {
        if self.memory.contains_key(&id) {return Ok(());}
        let Some(path)=self.path(id).filter(|p|fs::metadata(p).is_ok_and(|m|m.len()!=4)) else {return Ok(());};
        self.room()?;
        let result=(||{
            let value:serde_json::Value=serde_json::from_slice(&fs::read(&path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
            let mut e:Exchange=serde_json::from_value(value["exchange"].clone()).map_err(|e|e.to_string())?;
            if let Some(id)=value["cache_id"].as_u64() {
                e.cache=Some(self.store.as_ref().unwrap().0.reference(id)?);
                for (side,m) in [(0,&mut e.request),(1,&mut e.response)] {
                    if let Some(m)=m {m.cache_writer=e.cache.clone().map(|c|(c,side));}
                }
            }
            Ok::<_,String>(e)
        })();
        match result {
            Ok(e)=>{self.memory.insert(id,e);Ok(())}
            Err(e)=>{self.store.as_ref().unwrap().0.fail_recording(&format!("analysis state read failed: {e}"));Err(e)}
        }
    }
    pub fn get_mut(&mut self,id:&u64)->Result<Option<&mut Exchange>,String> {
        self.load(*id)?;Ok(self.memory.get_mut(id))
    }
    pub fn remove(&mut self,id:&u64)->Result<Option<Exchange>,String> {
        self.load(*id)?;
        // Retire disposable parser state; payload and recording events remain.
        if let Some((c,dir))=&self.store {
            if self.path(*id).is_some_and(|p|p.exists()) {
                c.working_write(format!("{dir}/{id}.json"),b"null".to_vec())?;
            }
        }
        Ok(self.memory.remove(id))
    }
    pub fn keys(&self)->Result<Box<dyn Iterator<Item=Result<u64,String>>>,String> {
        let memory:std::collections::BTreeSet<u64>=self.memory.keys().copied().collect();
        let first:Vec<_>=memory.iter().copied().map(Ok).collect();
        let disk=if let Some((c,dir))=&self.store {
            let dir=c.directory().join(dir);
            if dir.exists() {Some(fs::read_dir(dir).map_err(|e|e.to_string())?)}else{None}
        }else{None};
        let entries=disk.into_iter().flatten().filter_map(move |entry| {
            let entry=match entry {Ok(e)=>e,Err(e)=>return Some(Err(e.to_string()))};
            let path=entry.path();if path.extension().and_then(|s|s.to_str())!=Some("json") {return None;}
            let id=path.file_stem().and_then(|s|s.to_str()).and_then(|s|s.parse().ok())?;
            if memory.contains(&id) {return None;}
            match entry.metadata() {Ok(m) if m.len()==4=>None,Ok(_)=>Some(Ok(id)),Err(e)=>Some(Err(e.to_string()))}
        });
        Ok(Box::new(first.into_iter().chain(entries)))
    }
    pub fn drain(&mut self,reason:&str)->Vec<Exchange> {
        let mut out=Vec::new();
        match self.keys().and_then(|ids|{
            for id in ids {if let Some(mut e)=self.remove(&id?)? {
                e.problem=Some(reason.into());e.finish_cache();
                // Every exchange is recorded; only the UI result tail is bounded.
                if self.store.is_some() && out.len()>=self.limit {out.remove(0);}
                out.push(e);
            }}
            Ok(())
        }) {
            Ok(())=>(),
            Err(e)=>if let Some((c,_))=&self.store {c.fail_recording(&format!("analysis state drain failed: {e}"));},
        }
        out
    }
}
