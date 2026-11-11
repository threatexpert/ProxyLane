#pragma once
#include <shellapi.h>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#pragma comment(lib,"shell32.lib")

// Page-owned, bounded cache. Only the UI touches image-list indices; the worker
// owns its queue/results and never holds a window pointer or calls a UI control.
class ProcessIconCache {
public:
    enum { Capacity=256, BatchSize=8 };
    struct Icon {
        std::wstring path;
        HICON handle=nullptr;
        ~Icon() {if(handle) DestroyIcon(handle);}
    };
private:
    struct State {
        std::mutex mutex;
        std::condition_variable wake;
        bool stop=false;
        std::deque<std::wstring> pending;
        std::deque<std::unique_ptr<Icon>> ready;
    };
    std::shared_ptr<State> m_state;
    std::map<std::wstring,int> m_indices;
    static void Worker(std::shared_ptr<State> state) {
        for (;;) {
            std::wstring path;
            {
                std::unique_lock<std::mutex> lock(state->mutex);
                state->wake.wait(lock,[&]{return state->stop || !state->pending.empty();});
                if(state->stop) return;
                path=std::move(state->pending.front());state->pending.pop_front();
            }
            std::unique_ptr<Icon> icon(new Icon);icon->path=path;
            // No shell extension handlers, PID queries or remote executable reads.
            // Missing/protected files get the same cached fallback as extraction failures.
            wchar_t root[]={path[0],L':',L'\\',0};
            if(GetDriveTypeW(root)==DRIVE_FIXED)
                ExtractIconExW(path.c_str(),0,nullptr,&icon->handle,1);
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                if(state->stop) return;
                state->ready.push_back(std::move(icon));
            }
        }
    }
public:
    ProcessIconCache()=default;
    ProcessIconCache(const ProcessIconCache&)=delete;
    ProcessIconCache& operator=(const ProcessIconCache&)=delete;
    ~ProcessIconCache() {
        if(m_state) {
            {std::lock_guard<std::mutex> lock(m_state->mutex);m_state->stop=true;m_state->pending.clear();}
            m_state->wake.notify_one();
        }
        // Do not wait for file I/O during window destruction. The detached worker
        // retains only State and releases any late result without touching the page.
    }
    static std::wstring Key(const CString& value) {
        CString path=value;
        if(path.Left(4)==L"\\\\?\\") path=path.Mid(4);
        if(path.GetLength()<3 || path.GetLength()>32767 || path[1]!=L':' || path[2]!=L'\\' ||
            !((path[0]>=L'A' && path[0]<=L'Z') || (path[0]>=L'a' && path[0]<=L'z'))) return {};
        path.MakeLower();return std::wstring(path.GetString(),path.GetLength());
    }
    int Lookup(const std::wstring& key) const {
        auto found=m_indices.find(key);return found==m_indices.end()?0:found->second;
    }
    int Request(const std::wstring& key) {
        if(key.empty()) return 0;
        auto found=m_indices.find(key);if(found!=m_indices.end()) return found->second;
        if(m_indices.size()>=Capacity) return 0;
        try {
            m_indices.emplace(key,0); // Cache failures too: never retry on every poll.
            if(!m_state) {
                auto state=std::make_shared<State>();
                std::thread worker([state]{try {Worker(state);} catch (...) {
                    // A failed optional worker must never terminate the host.
                    std::lock_guard<std::mutex> lock(state->mutex);state->stop=true;state->pending.clear();
                }});worker.detach();m_state=state;
            }
            {std::lock_guard<std::mutex> lock(m_state->mutex);if(m_state->stop) return 0;m_state->pending.push_back(key);}
            m_state->wake.notify_one();
        } catch (...) {} // Icons are optional; monitoring remains usable on allocation/thread failure.
        return 0;
    }
    bool Apply(CImageList& images) {
        if(!m_state) return false;
        std::deque<std::unique_ptr<Icon>> ready;
        {
            std::lock_guard<std::mutex> lock(m_state->mutex);
            for(int n=0;n<BatchSize && !m_state->ready.empty();++n) {
                ready.push_back(std::move(m_state->ready.front()));m_state->ready.pop_front();
            }
        }
        bool changed=false;
        for(auto& icon:ready) if(icon->handle) {
            int index=images.Add(icon->handle);
            if(index>=0) {m_indices[icon->path]=index;changed=true;}
        }
        return changed;
    }
    size_t Size() const {return m_indices.size();}
};
