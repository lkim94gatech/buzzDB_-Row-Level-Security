#include <iostream>
#include <map>
#include <vector>
#include <fstream>
#include <iostream>
#include <chrono>

#include <list>
#include <unordered_map>
#include <iostream>
#include <map>
#include <string>
#include <memory>
#include <sstream>
#include <limits>
#include <thread>
#include <queue>
#include <optional>
#include <regex>
#include <stdexcept>
#include <cassert>
#include <optional>
#include <set>

struct Table {
    std::string name;
    std::vector<std::string> columns;
};

class TableManager {
private:
    std::unordered_map<std::string, Table> tables; // Map to store table information

public:
    void createTable(const std::string& tableName, const std::vector<std::string>& columns);
    void displayTables(); // Optional: To list all created tables
};

void TableManager::createTable(const std::string& tableName, const std::vector<std::string>& columns) {
    if (tables.find(tableName) != tables.end()) {
        throw std::runtime_error("Table already exists: " + tableName);
    }

    Table newTable;
    newTable.name = tableName;
    newTable.columns = columns;

    tables[tableName] = newTable;
    std::cout << "Table '" << tableName << "' created with columns: ";
    for (const auto& column : columns) {
        std::cout << column << " ";
    }
    std::cout << std::endl;
}

void assignRoleToUser(const std::string& username, const std::string& role) {
    std::unordered_map<std::string, User> users;
    std::unordered_map<std::string, Role> roles;

    auto user_it = users.find(username);
    if (user_it == users.end()) {
        throw std::runtime_error("User not found: " + username);
    }

    auto role_it = roles.find(role);
    if (role_it == roles.end()) {
        throw std::runtime_error("Role not found: " + role);
    }

    std::cout << "Assigned role '" << role << "' to user '" << username << "'." << std::endl;
}

class UserManager {
public:
    void assignRoleToUser(const std::string& username, const std::string& role);
};


class SecurityLogger {
private:
    static AuditTrail audit_trail;

public:
    static AuditTrail& getAuditTrail() {
        return audit_trail;
    }

    static void logAccessDenied(const std::string& username, int attempted_level, const std::string& operation) {
        std::cerr << "Access Denied - User: " << username 
                  << " attempted to access level " << attempted_level 
                  << " during " << operation << std::endl;
                  
        audit_trail.logEvent(
            username,
            AuditTrail::EventType::SECURITY_VIOLATION,
            "N/A",
            operation,
            attempted_level,
            false,
            "Access level violation"
        );
    }
    
    static void logAccessViolation(const std::string& username, const std::string& violation) {
        std::cerr << "Security Violation - User: " << username 
                  << " - " << violation << std::endl;
                  
        audit_trail.logEvent(
            username,
            AuditTrail::EventType::SECURITY_VIOLATION,
            "N/A",
            "violation",
            0,
            false,
            violation
        );
    }
};

class AuditTrail {
public:
    enum class EventType {
        ACCESS_ATTEMPT,
        PERMISSION_CHANGE,
        DATA_MODIFICATION,
        SECURITY_VIOLATION,
        LOGIN_ATTEMPT,
        ROLE_CHANGE,
        QUERY_EXECUTION,
        ACCESS_VIOLATION
    };

    struct AuditEvent {
        std::chrono::system_clock::time_point timestamp;
        std::string username;
        EventType type;
        std::string table;
        std::string operation;
        int access_level;
        bool success;
        std::string details;
    };

private:
    std::vector<AuditEvent> events;
    mutable std::mutex audit_mutex;
    static constexpr size_t MAX_EVENTS = 10000;
    std::string audit_file = "audit_log.txt";
    bool enable_persistence;

public:
    AuditTrail(bool persistence = true) : enable_persistence(persistence) {
        if (enable_persistence) {
            loadPersistedEvents();
        }
    }

    ~AuditTrail() {
        if (enable_persistence) {
            persistEvents();
        }
    }

    void logEvent(const std::string& username, 
                 EventType type,
                 const std::string& table,
                 const std::string& operation,
                 int access_level,
                 bool success,
                 const std::string& details = "") {
        std::lock_guard<std::mutex> lock(audit_mutex);
        
        if (events.size() >= MAX_EVENTS) {
            persistEvents();
        }

        events.push_back({
            std::chrono::system_clock::now(),
            username,
            type,
            table,
            operation,
            access_level,
            success,
            details
        });

        if (enable_persistence && 
            (type == EventType::SECURITY_VIOLATION || !success)) {
            persistImmediately(events.back());
        }
    }

    std::vector<AuditEvent> getEvents(
        const std::string& username = "",
        const std::chrono::system_clock::time_point& start = std::chrono::system_clock::time_point::min(),
        const std::chrono::system_clock::time_point& end = std::chrono::system_clock::time_point::max()) const 
    {
        std::lock_guard<std::mutex> lock(audit_mutex);
        std::vector<AuditEvent> filtered;
        
        std::copy_if(events.begin(), events.end(), std::back_inserter(filtered),
            [&](const AuditEvent& event) {
                bool timeMatch = event.timestamp >= start && event.timestamp <= end;
                bool userMatch = username.empty() || event.username == username;
                return timeMatch && userMatch;
            });
            
        return filtered;
    }

    void clearEvents() {
        std::lock_guard<std::mutex> lock(audit_mutex);
        events.clear();
    }

    size_t getEventCount() const {
        std::lock_guard<std::mutex> lock(audit_mutex);
        return events.size();
    }

    std::vector<AuditEvent> getViolations(const std::string& username = "") const {
        std::lock_guard<std::mutex> lock(audit_mutex);
        std::vector<AuditEvent> violations;
        
        std::copy_if(events.begin(), events.end(), std::back_inserter(violations),
            [&](const AuditEvent& event) {
                bool isViolation = event.type == EventType::SECURITY_VIOLATION || !event.success;
                bool userMatch = username.empty() || event.username == username;
                return isViolation && userMatch;
            });
            
        return violations;
    }

    void generateReport(std::ostream& out) const {
        std::lock_guard<std::mutex> lock(audit_mutex);
        out << "=== Security Audit Report ===\n";
        out << "Total Events: " << events.size() << "\n";
        
        std::map<std::string, int> userViolations;
        std::map<EventType, int> eventTypeCounts;
        
        for (const auto& event : events) {
            eventTypeCounts[event.type]++;
            if (!event.success) {
                userViolations[event.username]++;
            }
        }

        out << "\nEvent Type Distribution:\n";
        for (const auto& [type, count] : eventTypeCounts) {
            out << "- " << static_cast<int>(type) << ": " << count << "\n";
        }

        out << "\nSecurity Violations by User:\n";
        for (const auto& [user, count] : userViolations) {
            out << "- " << user << ": " << count << "\n";
        }
    }

private:
    void persistEvents() {
        if (!enable_persistence) return;
        
        std::ofstream out(audit_file, std::ios::app);
        for (const auto& event : events) {
            persistEvent(out, event);
        }
        events.clear();
    }

    void persistImmediately(const AuditEvent& event) {
        std::ofstream out(audit_file, std::ios::app);
        persistEvent(out, event);
    }

    void persistEvent(std::ofstream& out, const AuditEvent& event) {
        auto time_t = std::chrono::system_clock::to_time_t(event.timestamp);
        out << std::ctime(&time_t) 
            << "|" << event.username 
            << "|" << static_cast<int>(event.type)
            << "|" << event.table
            << "|" << event.operation
            << "|" << event.access_level
            << "|" << event.success
            << "|" << event.details
            << std::endl;
    }

    void loadPersistedEvents() {
        std::ifstream in(audit_file);
        std::string line;
        
        // while (std::getline(in, line)) {}
    }
};

class TablePermissions {
public:
    struct TableSchema {
        std::string table_name;
        std::vector<std::string> column_names;
        std::unordered_map<std::string, std::set<std::string>> foreign_keys;
    };

    static std::unordered_map<std::string, TableSchema> schemas;
};

class Permission {
public:
    enum AccessType { READ, WRITE, DELETE, ALL };
    enum JoinAccess { NONE, INNER, LEFT, RIGHT, FULL };
    
    std::string table_name;
    AccessType access_type;
    int minimum_access_level;
    std::unordered_map<std::string, JoinAccess> join_permissions;
    
    Permission(std::string table, AccessType type, int level) 
        : table_name(table), access_type(type), minimum_access_level(level) {}
    
    void addJoinPermission(const std::string& target_table, JoinAccess access) {
        join_permissions[target_table] = access;
    }

    bool canJoin(const std::string& target_table, JoinAccess required_access) const {
        auto it = join_permissions.find(target_table);
        return it != join_permissions.end() && it->second >= required_access;
    }
};

class Role {
public:
    std::string role_name;
    std::vector<Permission> permissions;
    
    Role(std::string name) : role_name(name) {}
    
    void addPermission(Permission perm) {
        permissions.push_back(perm);
    }
    
    bool canAccess(const std::string& table, Permission::AccessType type, int level) const {
        for (const auto& perm : permissions) {
            if (perm.table_name == table && 
                (perm.access_type == Permission::ALL || perm.access_type >= type) && 
                perm.minimum_access_level >= level) {
                return true;
            }
        }
        return false;
    }
};

class RoleManager {
private:
    std::unordered_map<std::string, Role*> role_hierarchy;
    static RoleManager* instance;

public:
    static RoleManager& getInstance() {
        if (!instance) {
            instance = new RoleManager();
        }
        return *instance;
    }

    void updatePermission(const std::string& role_name, 
                         const std::string& table,
                         Permission::AccessType new_type,
                         int new_level) {
        auto role = role_hierarchy[role_name];
        for (auto& perm : role->permissions) {
            if (perm.table_name == table) {
                perm.access_type = new_type;
                perm.minimum_access_level = new_level;
                break;
            }
        }
    }
    
    void inheritPermissions(const std::string& child_role, 
                          const std::string& parent_role) {
        auto parent = role_hierarchy[parent_role];
        auto child = role_hierarchy[child_role];
        
        for (const auto& perm : parent->permissions) {
            bool has_perm = false;
            for (const auto& child_perm : child->permissions) {
                if (child_perm.table_name == perm.table_name) {
                    has_perm = true;
                    break;
                }
            }
            if (!has_perm) {
                child->addPermission(perm);
            }
        }
    }
};

RoleManager* RoleManager::instance = nullptr;

enum FieldType { INT, FLOAT, STRING };

class User {
public:
    std::string username;
    std::vector<Role> roles;
    int access_level;

    User(const std::string& name, int level) 
        : username(name), access_level(level) {}

    void addRole(const Role& role) {
        roles.push_back(role);
    }

    bool canAccess(int row_access_level) const {
        if (access_level >= row_access_level) {
            return true;
        }

        for (const auto& role : roles) {
            if (role.canAccess("default", Permission::READ, row_access_level)) {
                return true;
            }
        }
        return false;
    }

    bool canAccess(const std::string& table, Permission::AccessType type, int level) const {
        for (const auto& role : roles) {
            if (role.canAccess(table, type, level)) {
                return true;
            }
        }
        return false;
    }
};

class Field {
public:
    FieldType type;
    size_t data_length;
    std::unique_ptr<char[]> data;

public:
    Field(int i) : type(INT) { 
        data_length = sizeof(int);
        data = std::make_unique<char[]>(data_length);
        std::memcpy(data.get(), &i, data_length);
    }

    Field(float f) : type(FLOAT) { 
        data_length = sizeof(float);
        data = std::make_unique<char[]>(data_length);
        std::memcpy(data.get(), &f, data_length);
    }

    Field(const std::string& s) : type(STRING) {
        data_length = s.size() + 1;  // include null-terminator
        data = std::make_unique<char[]>(data_length);
        std::memcpy(data.get(), s.c_str(), data_length);
    }

    Field& operator=(const Field& other) {
        if (&other == this) {
            return *this;
        }
        type = other.type;
        data_length = other.data_length;
        std::memcpy(data.get(), other.data.get(), data_length);
        return *this;
    }

    Field(const Field& other) : type(other.type), data_length(other.data_length), data(new char[data_length]) {
        std::memcpy(data.get(), other.data.get(), data_length);
    }

    // Field(Field&& other) noexcept : type(other.type), data_length(other.data_length), data(std::move(other.data)) {}

    FieldType getType() const { return type; }
    int asInt() const { 
        return *reinterpret_cast<int*>(data.get());
    }
    float asFloat() const { 
        return *reinterpret_cast<float*>(data.get());
    }
    std::string asString() const { 
        return std::string(data.get());
    }

    std::string serialize() {
        std::stringstream buffer;
        buffer << type << ' ' << data_length << ' ';
        if (type == STRING) {
            buffer << data.get() << ' ';
        } else if (type == INT) {
            buffer << *reinterpret_cast<int*>(data.get()) << ' ';
        } else if (type == FLOAT) {
            buffer << *reinterpret_cast<float*>(data.get()) << ' ';
        }
        return buffer.str();
    }

    void serialize(std::ofstream& out) {
        std::string serializedData = this->serialize();
        out << serializedData;
    }

    static std::unique_ptr<Field> deserialize(std::istream& in) {
        int type; in >> type;
        size_t length; in >> length;
        if (type == STRING) {
            std::string val; in >> val;
            return std::make_unique<Field>(val);
        } else if (type == INT) {
            int val; in >> val;
            return std::make_unique<Field>(val);
        } else if (type == FLOAT) {
            float val; in >> val;
            return std::make_unique<Field>(val);
        }
        return nullptr;
    }

    std::unique_ptr<Field> clone() const {
        return std::make_unique<Field>(*this);
    }

    void print() const{
        switch(getType()){
            case INT: std::cout << asInt(); break;
            case FLOAT: std::cout << asFloat(); break;
            case STRING: std::cout << asString(); break;
        }
    }
};

bool operator==(const Field& lhs, const Field& rhs) {
    if (lhs.type != rhs.type) return false;

    switch (lhs.type) {
        case INT:
            return *reinterpret_cast<const int*>(lhs.data.get()) == *reinterpret_cast<const int*>(rhs.data.get());
        case FLOAT:
            return *reinterpret_cast<const float*>(lhs.data.get()) == *reinterpret_cast<const float*>(rhs.data.get());
        case STRING:
            return std::string(lhs.data.get(), lhs.data_length - 1) == std::string(rhs.data.get(), rhs.data_length - 1);
        default:
            throw std::runtime_error("Unsupported field type for comparison.");
    }
}

class Tuple {
public:
    std::vector<std::unique_ptr<Field>> fields;
    int access_level; // ROW-LEVEL SECURITY

    Tuple(int level = 0) : access_level(level) {}

    void addField(std::unique_ptr<Field> field) {
        fields.push_back(std::move(field));
    }

    size_t getSize() const {
        size_t size = 0;
        for (const auto& field : fields) {
            size += field->data_length;
        }
        return size;
    }

    // security methods
    bool isAccessibleTo(const User& user) const {
        return user.canAccess(access_level);
    }

    std::string serialize() {
        std::stringstream buffer;
        // <access_level> <field_count> <fields...>
        buffer << "ACCESS:" << access_level << " ";
        buffer << "FIELDS:" << fields.size() << " ";
        for (const auto& field : fields) {
            buffer << field->serialize();
        }
        return buffer.str();
    }

    void serialize(std::ofstream& out) {
        std::string serializedData = this->serialize();
        out << serializedData;
    }

    static std::unique_ptr<Tuple> deserialize(std::istream& in, const User* current_user = nullptr) {
        std::string input;
        std::getline(in, input);
        std::istringstream iss(input);
        std::string marker;
        int access_level;
        size_t field_count;
        
        iss >> marker >> access_level;
        if(marker != "ACCESS:") {
            return nullptr;
        }
        
        iss >> marker >> field_count;
        if(marker != "FIELDS:") {
            return nullptr;
        }

        if (current_user && !current_user->canAccess(access_level)) {
            SecurityLogger::logAccessDenied(current_user->username, 
                                         access_level, 
                                         "tuple deserialization");
            return nullptr;
        }

        auto tuple = std::make_unique<Tuple>(access_level);
        for (size_t i = 0; i < field_count; ++i) {
            auto field = Field::deserialize(in);
            if (field) {
                tuple->addField(std::move(field));
            }
        }
        return tuple;
    }

    std::unique_ptr<Tuple> clone() const {
        auto clonedTuple = std::make_unique<Tuple>(access_level);
        for (const auto& field : fields) {
            clonedTuple->addField(field->clone());
        }
        return clonedTuple;
    }

    void print() const {
        for (const auto& field : fields) {
            field->print();
            std::cout << " ";
        }
        std::cout << "\n";
    }
};

static constexpr size_t PAGE_SIZE = 4096;
static constexpr size_t MAX_SLOTS = 512;
uint16_t INVALID_VALUE = std::numeric_limits<uint16_t>::max();

struct Slot {
    bool empty = true;  
    uint16_t offset = INVALID_VALUE;
    uint16_t length = INVALID_VALUE;
};

// Slotted Page class
class SlottedPage {
public:
    std::unique_ptr<char[]> page_data = std::make_unique<char[]>(PAGE_SIZE);
    size_t metadata_size = sizeof(Slot) * MAX_SLOTS;

    SlottedPage(){
        Slot* slot_array = reinterpret_cast<Slot*>(page_data.get());
        for (size_t slot_itr = 0; slot_itr < MAX_SLOTS; slot_itr++) {
            slot_array[slot_itr].empty = true;
            slot_array[slot_itr].offset = INVALID_VALUE;
            slot_array[slot_itr].length = INVALID_VALUE;
        }
    }

    bool addTuple(std::unique_ptr<Tuple> tuple) {

        auto serializedTuple = tuple->serialize();
        size_t tuple_size = serializedTuple.size();

        //std::cout << "Tuple size: " << tuple_size << " bytes\n";
        // assert(tuple_size >= 40 && tuple_size <= 45);
        if (tuple_size >= PAGE_SIZE) {
            return false;
        }

        size_t slot_itr = 0;
        Slot* slot_array = reinterpret_cast<Slot*>(page_data.get());        
        for (; slot_itr < MAX_SLOTS; slot_itr++) {
            if (slot_array[slot_itr].empty == true and 
                slot_array[slot_itr].length >= tuple_size) {
                break;
            }
        }
        if (slot_itr == MAX_SLOTS){
            //std::cout << "Page does not contain an empty slot with sufficient space to store the tuple.";
            return false;
        }

        slot_array[slot_itr].empty = false;
        size_t offset = INVALID_VALUE;
        if (slot_array[slot_itr].offset == INVALID_VALUE){
            if(slot_itr != 0){
                auto prev_slot_offset = slot_array[slot_itr - 1].offset;
                auto prev_slot_length = slot_array[slot_itr - 1].length;
                offset = prev_slot_offset + prev_slot_length;
            }
            else{
                offset = metadata_size;
            }

            slot_array[slot_itr].offset = offset;
        }
        else{
            offset = slot_array[slot_itr].offset;
        }

        if(offset + tuple_size >= PAGE_SIZE){
            slot_array[slot_itr].empty = true;
            slot_array[slot_itr].offset = INVALID_VALUE;
            return false;
        }

        assert(offset != INVALID_VALUE);
        assert(offset >= metadata_size);
        assert(offset + tuple_size < PAGE_SIZE);

        if (slot_array[slot_itr].length == INVALID_VALUE){
            slot_array[slot_itr].length = tuple_size;
        }

        std::memcpy(page_data.get() + offset, 
                    serializedTuple.c_str(), 
                    tuple_size);

        return true;
    }

    void deleteTuple(size_t index) {
        Slot* slot_array = reinterpret_cast<Slot*>(page_data.get());
        size_t slot_itr = 0;
        for (; slot_itr < MAX_SLOTS; slot_itr++) {
            if(slot_itr == index and
               slot_array[slot_itr].empty == false){
                slot_array[slot_itr].empty = true;
                break;
               }
        }

        //std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void print() const{
        Slot* slot_array = reinterpret_cast<Slot*>(page_data.get());
        for (size_t slot_itr = 0; slot_itr < MAX_SLOTS; slot_itr++) {
            if (slot_array[slot_itr].empty == false){
                assert(slot_array[slot_itr].offset != INVALID_VALUE);
                const char* tuple_data = page_data.get() + slot_array[slot_itr].offset;
                std::istringstream iss(tuple_data);
                auto loadedTuple = Tuple::deserialize(iss);
                std::cout << "Slot " << slot_itr << " : [";
                std::cout << (uint16_t)(slot_array[slot_itr].offset) << "] :: ";
                loadedTuple->print();
            }
        }
        std::cout << "\n";
    }
};

const std::string database_filename = "buzzdb.dat";

class StorageManager {
public:    
    std::fstream fileStream;
    size_t num_pages = 0;

public:
    StorageManager(){
        fileStream.open(database_filename, std::ios::in | std::ios::out);
        if (!fileStream) {
            fileStream.clear();
            fileStream.open(database_filename, std::ios::out);
        }
        fileStream.close(); 
        fileStream.open(database_filename, std::ios::in | std::ios::out); 

        fileStream.seekg(0, std::ios::end);
        num_pages = fileStream.tellg() / PAGE_SIZE;

        std::cout << "Storage Manager :: Num pages: " << num_pages << "\n";        
        if(num_pages == 0){
            extend();
        }

    }

    ~StorageManager() {
        if (fileStream.is_open()) {
            fileStream.close();
        }
    }

    std::unique_ptr<SlottedPage> load(uint16_t page_id) {
        fileStream.seekg(page_id * PAGE_SIZE, std::ios::beg);
        auto page = std::make_unique<SlottedPage>();
        if(fileStream.read(page->page_data.get(), PAGE_SIZE)){
            //std::cout << "Page read successfully from file." << std::endl;
        }
        else{
            std::cerr << "Error: Unable to read data from the file. \n";
            exit(-1);
        }
        return page;
    }

    void flush(uint16_t page_id, const std::unique_ptr<SlottedPage>& page) {
        size_t page_offset = page_id * PAGE_SIZE;        

        fileStream.seekp(page_offset, std::ios::beg);
        fileStream.write(page->page_data.get(), PAGE_SIZE);        
        fileStream.flush();
    }

    void extend() {
        std::cout << "Extending database file \n";

        // Create a slotted page
        auto empty_slotted_page = std::make_unique<SlottedPage>();

        // Move the write pointer
        fileStream.seekp(0, std::ios::end);

        // Write the page to the file, extending it
        fileStream.write(empty_slotted_page->page_data.get(), PAGE_SIZE);
        fileStream.flush();

        // Update number of pages
        num_pages += 1;
    }

};

using PageID = uint16_t;

class Policy {
public:
    virtual bool touch(PageID page_id) = 0;
    virtual PageID evict() = 0;
    virtual ~Policy() = default;
};

void printList(std::string list_name, const std::list<PageID>& myList) {
        std::cout << list_name << " :: ";
        for (const PageID& value : myList) {
            std::cout << value << ' ';
        }
        std::cout << '\n';
}

class LruPolicy : public Policy {
private:
    // List to keep track of the order of use
    std::list<PageID> lruList;

    // Map to find a page's iterator in the list efficiently
    std::unordered_map<PageID, std::list<PageID>::iterator> map;

    size_t cacheSize;

public:

    LruPolicy(size_t cacheSize) : cacheSize(cacheSize) {}

    bool touch(PageID page_id) override {
        //printList("LRU", lruList);

        bool found = false;
        // If page already in the list, remove it
        if (map.find(page_id) != map.end()) {
            found = true;
            lruList.erase(map[page_id]);
            map.erase(page_id);            
        }

        // If cache is full, evict
        if(lruList.size() == cacheSize){
            evict();
        }

        if(lruList.size() < cacheSize){
            // Add the page to the front of the list
            lruList.emplace_front(page_id);
            map[page_id] = lruList.begin();
        }

        return found;
    }

    PageID evict() override {
        // Evict the least recently used page
        PageID evictedPageId = INVALID_VALUE;
        if(lruList.size() != 0){
            evictedPageId = lruList.back();
            map.erase(evictedPageId);
            lruList.pop_back();
        }
        return evictedPageId;
    }

};

constexpr size_t MAX_PAGES_IN_MEMORY = 10;

class BufferManager {
private:
    using PageMap = std::unordered_map<PageID, std::unique_ptr<SlottedPage>>;

    StorageManager storage_manager;
    PageMap pageMap;
    std::unique_ptr<Policy> policy;

public:
    BufferManager(): 
    policy(std::make_unique<LruPolicy>(MAX_PAGES_IN_MEMORY)) {}

    std::unique_ptr<SlottedPage>& getPage(int page_id) {
        auto it = pageMap.find(page_id);
        if (it != pageMap.end()) {
            policy->touch(page_id);
            return pageMap.find(page_id)->second;
        }

        if (pageMap.size() >= MAX_PAGES_IN_MEMORY) {
            auto evictedPageId = policy->evict();
            if(evictedPageId != INVALID_VALUE){
                std::cout << "Evicting page " << evictedPageId << "\n";
                storage_manager.flush(evictedPageId, 
                                      pageMap[evictedPageId]);
            }
        }

        auto page = storage_manager.load(page_id);
        policy->touch(page_id);
        std::cout << "Loading page: " << page_id << "\n";
        pageMap[page_id] = std::move(page);
        return pageMap[page_id];
    }

    void flushPage(int page_id) {
        //std::cout << "Flush page " << page_id << "\n";
        storage_manager.flush(page_id, pageMap[page_id]);
    }

    void extend(){
        storage_manager.extend();
    }
    
    size_t getNumPages(){
        return storage_manager.num_pages;
    }

};

class HashIndex {
private:
    struct HashEntry {
        int key;
        int value;
        int position;
        bool exists;

        HashEntry() : key(0), value(0), position(-1), exists(false) {}

        HashEntry(int k, int v, int pos) : key(k), value(v), position(pos), exists(true) {}    
    };

    static const size_t capacity = 100;
    HashEntry hashTable[capacity];

    size_t hashFunction(int key) const {
        return key % capacity; // Simple modulo hash function
    }

public:
    HashIndex() {
        // Initialize all entries as non-existing by default
        for (size_t i = 0; i < capacity; ++i) {
            hashTable[i] = HashEntry();
        }
    }

    void insertOrUpdate(int key, int value) {
        size_t index = hashFunction(key);
        size_t originalIndex = index;
        bool inserted = false;
        int i = 0; // Attempt counter

        do {
            if (!hashTable[index].exists) {
                hashTable[index] = HashEntry(key, value, true);
                hashTable[index].position = index;
                inserted = true;
                break;
            } else if (hashTable[index].key == key) {
                hashTable[index].value += value;
                hashTable[index].position = index;
                inserted = true;
                break;
            }
            i++;
            index = (originalIndex + i*i) % capacity; // Quadratic probing
        } while (index != originalIndex && !inserted);

        if (!inserted) {
            std::cerr << "HashTable is full or cannot insert key: " << key << std::endl;
        }
    }

   int getValue(int key) const {
        size_t index = hashFunction(key);
        size_t originalIndex = index;

        do {
            if (hashTable[index].exists && hashTable[index].key == key) {
                return hashTable[index].value;
            }
            if (!hashTable[index].exists) {
                break;
            }
            index = (index + 1) % capacity;
        } while (index != originalIndex);

        return -1; // Key not found
    }


    std::vector<int> rangeQuery(int lowerBound, int upperBound) const {
        std::vector<int> values;
        for (size_t i = 0; i < capacity; ++i) {
            if (hashTable[i].exists && hashTable[i].key >= lowerBound && hashTable[i].key <= upperBound) {
                std::cout << "Key: " << hashTable[i].key << 
                ", Value: " << hashTable[i].value << std::endl;
                values.push_back(hashTable[i].value);
            }
        }
        return values;
    }

    void print() const {
        for (size_t i = 0; i < capacity; ++i) {
            if (hashTable[i].exists) {
                std::cout << "Position: " << hashTable[i].position << 
                ", Key: " << hashTable[i].key << 
                ", Value: " << hashTable[i].value << std::endl;
            }
        }
    }
};

class Operator {
    public:
    virtual ~Operator() = default;
    virtual void open() = 0;
    virtual bool next() = 0;
    virtual void close() = 0;
    virtual std::vector<std::unique_ptr<Field>> getOutput() = 0;
};

class BaseOperator : public Operator {
protected:
    const User* current_user;
    std::string current_table;
    bool audit_mode;

    virtual void logOperatorEvent(const std::string& operation, bool success) {
        if (audit_mode) {
            SecurityLogger::getAuditTrail().logEvent(
                current_user ? current_user->username : "unknown",
                AuditTrail::EventType::QUERY_EXECUTION,
                current_table.empty() ? "unknown_table" : current_table,
                operation,
                current_user ? current_user->access_level : 0,
                success
            );
        }
    }

    void logAccessViolation(const std::string& reason) {
        if (audit_mode) {
            SecurityLogger::getAuditTrail().logEvent(
                current_user ? current_user->username : "unknown",
                AuditTrail::EventType::ACCESS_VIOLATION,
                current_table.empty() ? "unknown_table" : current_table,
                reason,
                current_user ? current_user->access_level : 0,
                false
            );
        }
    }

    bool validateUserContext() {
        if (!current_user) {
            logAccessViolation("No user context provided for operation");
            return false;
        }
        return true;
    }

public:
    BaseOperator(const User* user = nullptr, const std::string& table = "", bool enable_audit = false)
        : current_user(user), current_table(table), audit_mode(enable_audit) {}

    virtual ~BaseOperator() {}

    virtual void open() override {
        logOperatorEvent("open", true);
    }

    virtual bool next() override {
        logOperatorEvent("next", true);
        return false;
    }

    virtual void close() override {
        logOperatorEvent("close", true);
    }

    virtual std::vector<std::unique_ptr<Field>> getOutput() override {
        return {};
    }
};

class ScanOperator : public BaseOperator {
private:
    BufferManager& buffer_manager;
    size_t current_page;
    size_t current_slot;
    std::unique_ptr<Tuple> current_tuple;
    bool reached_end;

public:
    ScanOperator(BufferManager& manager, User* user, const std::string& table = "default")
        : buffer_manager(manager), current_page(0), current_slot(0), reached_end(false) {
        this->current_user = user;
        this->current_table = table;
    }

    void open() override {
        logOperatorEvent("scan_open", true);
        current_page = 0;
        current_slot = 0;
        reached_end = false;
        loadNextTuple();
    }

    bool next() override {
        if (reached_end) {
            logOperatorEvent("scan_next", false);
            return false;
        }

        while (true) {
            if (current_tuple && checkAccess(current_tuple.get())) {
                logOperatorEvent("scan_next", true);
                return true;
            }

            if (!loadNextTuple()) {
                reached_end = true;
                logOperatorEvent("scan_next", false);
                return false;
            }
        }
    }

    void close() override {
        logOperatorEvent("scan_close", true);
        current_tuple.reset();
        current_page = 0;
        current_slot = 0;
        reached_end = false;
    }

    std::vector<std::unique_ptr<Field>> getOutput() override {
        if (!current_tuple) return {};

        std::vector<std::unique_ptr<Field>> output;
        for (const auto& field : current_tuple->fields) {
            output.push_back(field->clone());
        }
        return output;
    }

private:
    bool loadNextTuple() {
        while (current_page < buffer_manager.getNumPages()) {
            auto& page = buffer_manager.getPage(current_page);
            Slot* slots = reinterpret_cast<Slot*>(page->page_data.get());

            while (current_slot < MAX_SLOTS) {
                if (!slots[current_slot].empty) {
                    const char* tuple_data = page->page_data.get() + slots[current_slot].offset;
                    std::istringstream iss(std::string(tuple_data, slots[current_slot].length));
                    current_tuple = Tuple::deserialize(iss, current_user);
                    if (current_tuple) {
                        current_slot++;
                        return true;
                    }
                }
                current_slot++;
            }

            current_slot = 0;
            current_page++;
        }

        return false;
    }

    bool checkAccess(const Tuple* tuple) {
        bool has_access = current_user->canAccess(current_table, Permission::READ, tuple->access_level);

        if (!has_access && audit_mode) {
            SecurityLogger::logAccessDenied(
                current_user->username,
                tuple->access_level,
                "scan operation on table " + current_table
            );
        }

        return has_access;
    }
};

class UnaryOperator : public Operator {
    protected:
    Operator* input;

    public:
    explicit UnaryOperator(Operator& input) : input(&input) {}

    ~UnaryOperator() override = default;
};

class BinaryOperator : public Operator {
    protected:
    Operator* input_left;
    Operator* input_right;

    public:
    explicit BinaryOperator(Operator& input_left, Operator& input_right)
        : input_left(&input_left), input_right(&input_right) {}

    ~BinaryOperator() override = default;
};

class SelectOperator : public BaseOperator {
private:
    std::unique_ptr<IPredicate> predicate;
    bool has_next;
    std::vector<std::unique_ptr<Field>> currentOutput;
    Operator* input;
    std::string current_table;

public:
    SelectOperator(Operator& input, std::unique_ptr<IPredicate> predicate, User* user,
                   const std::string& table = "default", bool enable_audit = false)
        : input(&input), current_table(table) {
        this->current_user = user;
        this->audit_mode = enable_audit;
    }

    const std::string& getCurrentTable() const {
        return current_table;
    }

    Operator* getInput() const {
        return input;
    }

    const std::string& getCurrentTable() const {
        return current_table;
    }

    void open() override {
        logOperatorEvent("select_open", true);
        input->open();
        has_next = false;
        currentOutput.clear();
    }

    bool next() override {
        if (!validateUserContext()) {
            return false;
        }

        while (input->next()) {
            auto output = input->getOutput();
            auto tuple = createTupleFromOutput(output);

            if (predicate->check(output) && checkAccess(tuple.get())) {
                currentOutput.clear();
                for (const auto& field : output) {
                    currentOutput.push_back(field->clone());
                }
                has_next = true;
                logOperatorEvent("select_next", true);
                return true;
            }
        }

        has_next = false;
        currentOutput.clear();
        logOperatorEvent("select_next", false);
        return false;
    }

    void close() override {
        logOperatorEvent("select_close", true);
        input->close();
        currentOutput.clear();
    }

    std::vector<std::unique_ptr<Field>> getOutput() override {
        if (!has_next) return {};

        std::vector<std::unique_ptr<Field>> outputCopy;
        for (const auto& field : currentOutput) {
            outputCopy.push_back(field->clone());
        }
        return outputCopy;
    }

private:
    bool checkUserContext() {
        if (!current_user) {
            if (audit_mode) {
                SecurityLogger::logAccessViolation("none", "No user context provided for select operation");
            }
            return false;
        }
        return true;
    }

    std::unique_ptr<Tuple> createTupleFromOutput(const std::vector<std::unique_ptr<Field>>& output) {
        auto tuple = std::make_unique<Tuple>();
        for (const auto& field : output) {
            tuple->addField(field->clone());
        }
        return tuple;
    }

    bool checkAccess(const Tuple* tuple) {
        bool has_access = current_user->canAccess(tuple->access_level) && 
                        current_user->canAccess(current_table, Permission::READ, tuple->access_level);

        if (!has_access) {
            logAccessViolation("select operation on table " + current_table); // Use BaseOperator method
        }

        return has_access;
    }

};

class IPredicate {
public:
    virtual ~IPredicate() = default;
    virtual bool check(const std::vector<std::unique_ptr<Field>>& tupleFields) const = 0;
    virtual std::unique_ptr<IPredicate> clone() const = 0;
};

void printTuple(const std::vector<std::unique_ptr<Field>>& tupleFields) {
    std::cout << "Tuple: [";
    for (const auto& field : tupleFields) {
        field->print();
        std::cout << " ";
    }
    std::cout << "]";
}

class SimplePredicate: public IPredicate {
public:
    enum OperandType { DIRECT, INDIRECT };
    enum ComparisonOperator { EQ, NE, GT, GE, LT, LE };

    struct Operand {
        std::unique_ptr<Field> directValue;
        size_t index;
        OperandType type;

        Operand(std::unique_ptr<Field> value) : directValue(std::move(value)), type(DIRECT) {}
        Operand(size_t idx) : index(idx), type(INDIRECT) {}
    };

    Operand left_operand;
    Operand right_operand;
    ComparisonOperator comparison_operator;

    SimplePredicate(Operand left, Operand right, ComparisonOperator op)
        : left_operand(std::move(left)), right_operand(std::move(right)), comparison_operator(op) {}

    bool check(const std::vector<std::unique_ptr<Field>>& tupleFields) const {
        const Field* leftField = nullptr;
        const Field* rightField = nullptr;

        if (left_operand.type == DIRECT) {
            leftField = left_operand.directValue.get();
        } else if (left_operand.type == INDIRECT) {
            leftField = tupleFields[left_operand.index].get();
        }

        if (right_operand.type == DIRECT) {
            rightField = right_operand.directValue.get();
        } else if (right_operand.type == INDIRECT) {
            rightField = tupleFields[right_operand.index].get();
        }

        if (leftField == nullptr || rightField == nullptr) {
            std::cerr << "Error: Invalid field reference.\n";
            return false;
        }

        if (leftField->getType() != rightField->getType()) {
            std::cerr << "Error: Comparing fields of different types.\n";
            return false;
        }

        switch (leftField->getType()) {
            case FieldType::INT: {
                int left_val = leftField->asInt();
                int right_val = rightField->asInt();
                return compare(left_val, right_val);
            }
            case FieldType::FLOAT: {
                float left_val = leftField->asFloat();
                float right_val = rightField->asFloat();
                return compare(left_val, right_val);
            }
            case FieldType::STRING: {
                std::string left_val = leftField->asString();
                std::string right_val = rightField->asString();
                return compare(left_val, right_val);
            }
            default:
                std::cerr << "Invalid field type\n";
                return false;
        }
    }


private:
    template<typename T>
    bool compare(const T& left_val, const T& right_val) const {
        switch (comparison_operator) {
            case ComparisonOperator::EQ: return left_val == right_val;
            case ComparisonOperator::NE: return left_val != right_val;
            case ComparisonOperator::GT: return left_val > right_val;
            case ComparisonOperator::GE: return left_val >= right_val;
            case ComparisonOperator::LT: return left_val < right_val;
            case ComparisonOperator::LE: return left_val <= right_val;
            default: std::cerr << "Invalid predicate type\n"; return false;
        }
    }
};

class ComplexPredicate : public IPredicate {
public:
    enum LogicOperator { AND, OR };

private:
    std::vector<std::unique_ptr<IPredicate>> predicates;
    LogicOperator logic_operator;

public:
    ComplexPredicate(LogicOperator op) : logic_operator(op) {}

    void addPredicate(std::unique_ptr<IPredicate> predicate) {
        predicates.push_back(std::move(predicate));
    }

    bool check(const std::vector<std::unique_ptr<Field>>& tupleFields) const {
        
        if (logic_operator == AND) {
            for (const auto& pred : predicates) {
                if (!pred->check(tupleFields)) {
                    return false;
                }
            }
            return true;
        } else if (logic_operator == OR) {
            for (const auto& pred : predicates) {
                if (pred->check(tupleFields)) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }


};

enum class AggrFuncType { COUNT, MAX, MIN, SUM };

struct AggrFunc {
    AggrFuncType func;
    size_t attr_index;
};

class HashAggregationOperator : public BaseOperator {
private:
    std::vector<size_t> group_by_attrs;
    std::vector<AggrFunc> aggr_funcs;
    std::vector<Tuple> output_tuples;
    size_t output_tuples_index = 0;
    Operator* input;
    bool audit_mode;


    struct GroupKey {
        std::vector<Field> fields;
        bool operator==(const GroupKey& other) const {
            if (fields.size() != other.fields.size()) return false;
            for (size_t i = 0; i < fields.size(); i++) {
                if (!(fields[i] == other.fields[i])) return false;
            }
            return true;
        }
    };

    struct GroupKeyHash {
        size_t operator()(const GroupKey& key) const {
            size_t hash = 0;
            for (const auto& field : key.fields) {
                std::hash<std::string> hasher;
                size_t field_hash = 0;
                switch (field.type) {
                    case INT:
                        field_hash = std::hash<int>{}(*reinterpret_cast<const int*>(field.data.get()));
                        break;
                    case FLOAT:
                        field_hash = std::hash<float>{}(*reinterpret_cast<const float*>(field.data.get()));
                        break;
                    case STRING:
                        field_hash = hasher(std::string(field.data.get(), field.data_length - 1));
                        break;
                }
                hash ^= field_hash + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            }
            return hash;
        }
    };

public:
    HashAggregationOperator(Operator& input, 
                           std::vector<size_t> group_by_attrs, 
                           std::vector<AggrFunc> aggr_funcs, 
                           User* user,
                           const std::string& table = "default",
                           bool enable_audit = false)
        : group_by_attrs(group_by_attrs), 
          aggr_funcs(aggr_funcs),
          input(&input),
          audit_mode(enable_audit) {
        this->current_user = user;
        this->current_table = table;
    }

    void open() override {
        logOperatorEvent("hash_agg_open", true);
        input->open();
        output_tuples_index = 0;
        output_tuples.clear();

        if (!checkUserContext()) {
            logOperatorEvent("hash_agg_open", false);
            return;
        }

        std::unordered_map<GroupKey, std::vector<Field>, GroupKeyHash> hash_table;
    }

    bool next() override {
        bool has_next = output_tuples_index < output_tuples.size();
        if (has_next) {
            output_tuples_index++;
            logOperatorEvent("hash_agg_next", true);
        } else {
            logOperatorEvent("hash_agg_next", false);
        }
        return has_next;
    }

    void close() override {
        logOperatorEvent("hash_agg_close", true);
        input->close();
        if (audit_mode) {
            std::cout << "HashAggregation Statistics:\n"
                     << "- Groups processed: " << output_tuples.size() << "\n"
                     << "- Table: " << current_table << "\n"
                     << "- User: " << (current_user ? current_user->username : "none") << "\n";
        }
    }

    std::vector<std::unique_ptr<Field>> getOutput() override {
        if (output_tuples_index == 0 || output_tuples_index > output_tuples.size()) {
            return {};
        }

        std::vector<std::unique_ptr<Field>> outputCopy;
        const auto& currentTuple = output_tuples[output_tuples_index - 1];
        for (const auto& field : currentTuple.fields) {
            outputCopy.push_back(field->clone());
        }
        return outputCopy;
    }

private:
    bool checkUserContext() {
        if (!current_user) {
            if (audit_mode) {
                SecurityLogger::logAccessViolation("none", "No user context provided for aggregation");
            }
            return false;
        }
        return true;
    }

    std::unique_ptr<Tuple> createTupleFromFields(const std::vector<std::unique_ptr<Field>>& fields) {
        auto tuple = std::make_unique<Tuple>();
        for (const auto& field : fields) {
            tuple->addField(field->clone());
        }
        return tuple;
    }

    bool checkAccess(const Tuple* tuple) {
        bool has_access = current_user->canAccess(tuple->access_level) && 
                         current_user->canAccess(current_table, Permission::READ, tuple->access_level);

        if (!has_access && audit_mode) {
            SecurityLogger::logAccessDenied(
                current_user->username,
                tuple->access_level,
                "aggregation operation on table " + current_table
            );
        }

        return has_access;
    }

    Field updateAggregate(const AggrFunc& aggrFunc, const Field& currentAggr, const Field& newValue) {
        if (currentAggr.getType() != newValue.getType()) {
            throw std::runtime_error("Mismatched Field types in aggregation.");
        }

        switch (aggrFunc.func) {
            case AggrFuncType::COUNT:
                return Field(currentAggr.asInt() + 1);
                
            case AggrFuncType::SUM:
                if (currentAggr.getType() == INT) {
                    return Field(currentAggr.asInt() + newValue.asInt());
                } else if (currentAggr.getType() == FLOAT) {
                    return Field(currentAggr.asFloat() + newValue.asFloat());
                }
                break;
                
            case AggrFuncType::MAX:
                if (currentAggr.getType() == INT) {
                    return Field(std::max(currentAggr.asInt(), newValue.asInt()));
                } else if (currentAggr.getType() == FLOAT) {
                    return Field(std::max(currentAggr.asFloat(), newValue.asFloat()));
                }
                break;
                
            case AggrFuncType::MIN:
                if (currentAggr.getType() == INT) {
                    return Field(std::min(currentAggr.asInt(), newValue.asInt()));
                } else if (currentAggr.getType() == FLOAT) {
                    return Field(std::min(currentAggr.asFloat(), newValue.asFloat()));
                }
                break;
        }

        throw std::runtime_error("Invalid aggregation operation or field type");
    }
};

class HashJoinOperator : public BinaryOperator {
private:
    std::vector<std::unique_ptr<Field>> currentOutput;
    std::unordered_multimap<std::string, std::vector<std::unique_ptr<Field>>> hash_table;
    const User* current_user;
    std::string current_table;
    bool audit_mode;
    size_t join_column_left;
    size_t join_column_right;
    bool done_building = false;
    std::vector<std::unique_ptr<Field>> current_right_tuple;

public:
    HashJoinOperator(Operator& left_input, 
                 Operator& right_input,
                 size_t join_col_left,
                 size_t join_col_right,
                 User* user,
                 const std::string& table = "default",
                 bool enable_audit = false)
    : BinaryOperator(left_input, right_input),
      current_user(user),
      current_table(table),
      join_column_left(join_col_left),
      join_column_right(join_col_right),
      audit_mode(enable_audit) {}

    void open() override {
        input_left->open();
        input_right->open();
        buildHashTable();
    }

    bool next() override {
        while (input_right->next()) {
            current_right_tuple = input_right->getOutput();
            std::string join_key = getJoinKey(current_right_tuple, join_column_right);
            
            auto range = hash_table.equal_range(join_key);
            for (auto it = range.first; it != range.second; ++it) {
                if (validateJoinAccess(it->second, current_right_tuple)) {
                    produceOutput(it->second, current_right_tuple);
                    return true;
                }
            }
        }
        return false;
    }

    void close() override {
        input_left->close();
        input_right->close();
        hash_table.clear();
        currentOutput.clear();
    }

    std::vector<std::unique_ptr<Field>> getOutput() override {
        std::vector<std::unique_ptr<Field>> output;
        for (const auto& field : currentOutput) {
            output.push_back(field->clone());
        }
        return output;
    }

private:
    void buildHashTable() {
        while (input_left->next()) {
            auto tuple = input_left->getOutput();
            std::string join_key = getJoinKey(tuple, join_column_left);
            
            std::vector<std::unique_ptr<Field>> tuple_copy;
            for (const auto& field : tuple) {
                tuple_copy.push_back(field->clone());
            }
            
            hash_table.emplace(join_key, std::move(tuple_copy));
        }
        done_building = true;
    }

    std::string getJoinKey(const std::vector<std::unique_ptr<Field>>& tuple, size_t join_col) {
        return tuple[join_col]->serialize();
    }

    bool validateJoinAccess(const std::vector<std::unique_ptr<Field>>& left_tuple,
                           const std::vector<std::unique_ptr<Field>>& right_tuple) {
        if (!current_user) return false;

        auto left = createTupleFromFields(left_tuple);
        auto right = createTupleFromFields(right_tuple);

        return current_user->canAccess(left->access_level) && 
               current_user->canAccess(right->access_level) &&
               current_user->canAccess(current_table, Permission::READ, 
                                     std::max(left->access_level, right->access_level));
    }

    void produceOutput(const std::vector<std::unique_ptr<Field>>& left_tuple,
                      const std::vector<std::unique_ptr<Field>>& right_tuple) {
        currentOutput.clear();
        
        for (const auto& field : left_tuple) {
            currentOutput.push_back(field->clone());
        }
        
        for (const auto& field : right_tuple) {
            currentOutput.push_back(field->clone());
        }
    }

    std::unique_ptr<Tuple> createTupleFromFields(const std::vector<std::unique_ptr<Field>>& fields) {
        auto tuple = std::make_unique<Tuple>();
        for (const auto& field : fields) {
            tuple->addField(field->clone());
        }
        return tuple;
    }
};

struct QueryComponents {
    std::vector<int> selectAttributes;
    bool sumOperation = false;
    int sumAttributeIndex = -1;
    bool groupBy = false;
    int groupByAttributeIndex = -1;
    bool whereCondition = false;
    int whereAttributeIndex = -1;
    int lowerBound = std::numeric_limits<int>::min();
    int upperBound = std::numeric_limits<int>::max();
    
    bool hasJoin = false;
    std::string leftTable = "default";
    std::string rightTable = "";
    size_t joinColumnLeft = 0;
    size_t joinColumnRight = 0;
    enum class JoinType { NONE, INNER, LEFT, RIGHT } joinType = JoinType::NONE;
};

QueryComponents parseQuery(const std::string& query) {
    QueryComponents components;
    std::regex selectRegex("\\{(\\d+)\\}(, \\{(\\d+)\\})?");
    std::smatch selectMatches;
    std::string::const_iterator queryStart(query.cbegin());
    while (std::regex_search(queryStart, query.cend(), selectMatches, selectRegex)) {
        for (size_t i = 1; i < selectMatches.size(); i += 2) {
            if (!selectMatches[i].str().empty()) {
                components.selectAttributes.push_back(std::stoi(selectMatches[i]) - 1);
            }
        }
        queryStart = selectMatches.suffix().first;
    }

    std::regex joinRegex("JOIN (\\w+) ON \\{(\\d+)\\} = \\{(\\d+)\\}");
    std::smatch joinMatches;
    if (std::regex_search(query, joinMatches, joinRegex)) {
        components.hasJoin = true;
        components.rightTable = joinMatches[1].str();
        components.joinColumnLeft = std::stoi(joinMatches[2]) - 1;
        components.joinColumnRight = std::stoi(joinMatches[3]) - 1;
        components.joinType = QueryComponents::JoinType::INNER;
    }

    std::regex sumRegex("SUM\\{(\\d+)\\}");
    std::smatch sumMatches;
    if (std::regex_search(query, sumMatches, sumRegex)) {
        components.sumOperation = true;
        components.sumAttributeIndex = std::stoi(sumMatches[1]) - 1;
    }

    std::regex groupByRegex("GROUP BY \\{(\\d+)\\}");
    std::smatch groupByMatches;
    if (std::regex_search(query, groupByMatches, groupByRegex)) {
        components.groupBy = true;
        components.groupByAttributeIndex = std::stoi(groupByMatches[1]) - 1;
    }

    std::regex whereRegex("\\{(\\d+)\\} > (\\d+) and \\{(\\d+)\\} < (\\d+)");
    std::smatch whereMatches;
    if (std::regex_search(query, whereMatches, whereRegex)) {
        components.whereCondition = true;
        components.whereAttributeIndex = std::stoi(whereMatches[1]) - 1;
        components.lowerBound = std::stoi(whereMatches[2]);
        
        if (std::stoi(whereMatches[3]) - 1 == components.whereAttributeIndex) {
            components.upperBound = std::stoi(whereMatches[4]);
        }
    }

    return components;
}

void executeQuery(const QueryComponents& components, 
                 BufferManager& buffer_manager, 
                 User* current_user) {
    
    std::cout << "Executing query for user: " << current_user->username 
              << " (access level: " << current_user->access_level << ")\n";

    std::unique_ptr<Operator> rootOp;

    if (components.hasJoin) {
        auto leftScan = std::make_unique<ScanOperator>(buffer_manager, current_user, components.leftTable);
        auto rightScan = std::make_unique<ScanOperator>(buffer_manager, current_user, components.rightTable);

        auto leftSecure = std::make_unique<SelectOperator>(
            *leftScan,
            SecurityFilter::createSecurityPredicate(current_user, components.leftTable),
            current_user,
            components.leftTable
        );

        auto rightSecure = std::make_unique<SelectOperator>(
            *rightScan,
            SecurityFilter::createSecurityPredicate(current_user, components.rightTable),
            current_user,
            components.rightTable
        );

        rootOp = std::make_unique<HashJoinOperator>(
            *leftSecure,
            *rightSecure,
            components.joinColumnLeft,
            components.joinColumnRight,
            current_user
        );
    } else {
        rootOp = std::make_unique<ScanOperator>(buffer_manager, current_user);
    }

    if (components.whereCondition) {
        auto predicate1 = std::make_unique<SimplePredicate>(
            SimplePredicate::Operand(components.whereAttributeIndex),
            SimplePredicate::Operand(std::make_unique<Field>(components.lowerBound)),
            SimplePredicate::ComparisonOperator::GT
        );

        auto predicate2 = std::make_unique<SimplePredicate>(
            SimplePredicate::Operand(components.whereAttributeIndex),
            SimplePredicate::Operand(std::make_unique<Field>(components.upperBound)),
            SimplePredicate::ComparisonOperator::LT
        );

        auto complexPredicate = std::make_unique<ComplexPredicate>(ComplexPredicate::LogicOperator::AND);
        complexPredicate->addPredicate(std::move(predicate1));
        complexPredicate->addPredicate(std::move(predicate2));

        rootOp = std::make_unique<SelectOperator>(
            *rootOp,
            std::move(complexPredicate),
            current_user
        );
    }

    if (components.sumOperation || components.groupBy) {
        std::vector<size_t> groupByAttrs;
        if (components.groupBy) {
            groupByAttrs.push_back(components.groupByAttributeIndex);
        }
        
        std::vector<AggrFunc> aggrFuncs{
            {AggrFuncType::SUM, static_cast<size_t>(components.sumAttributeIndex)}
        };

        rootOp = std::make_unique<HashAggregationOperator>(
            *rootOp,
            groupByAttrs,
            aggrFuncs,
            current_user
        );
    }

    rootOp->open();
    while (rootOp->next()) {
        const auto& output = rootOp->getOutput();
        std::cout << "Access Level " << current_user->access_level << ": ";
        for (const auto& field : output) {
            field->print();
            std::cout << " ";
        }
        std::cout << std::endl;
    }
    rootOp->close();
}

class InsertOperator : public Operator {
private:
    BufferManager& bufferManager;
    std::unique_ptr<Tuple> tupleToInsert;
    const User* current_user;
    std::string current_table;
    bool audit_mode;

public:
    InsertOperator(BufferManager& manager, User* user, const std::string& table = "default", bool enable_audit = false)
        : bufferManager(manager), current_user(user), current_table(table), audit_mode(enable_audit) {}

    void setTupleToInsert(std::unique_ptr<Tuple> tuple) {
        if (!checkInsertPermission(tuple.get())) {
            throw std::runtime_error("Insufficient privileges for insert operation");
        }
        tupleToInsert = std::move(tuple);
    }

    void open() override {}

    bool next() override {
        if (!tupleToInsert) return false;

        for (size_t pageId = 0; pageId < bufferManager.getNumPages(); ++pageId) {
            auto& page = bufferManager.getPage(pageId);
            if (page->addTuple(tupleToInsert->clone())) {
                bufferManager.flushPage(pageId);
                if (audit_mode) {
                    logAuditInfo("successful insert");
                }
                return true;
            }
        }

        bufferManager.extend();
        auto& newPage = bufferManager.getPage(bufferManager.getNumPages() - 1);
        if (newPage->addTuple(tupleToInsert->clone())) {
            bufferManager.flushPage(bufferManager.getNumPages() - 1);
            if (audit_mode) {
                logAuditInfo("successful insert with page extension");
            }
            return true;
        }

        return false;
    }

    void close() override {}
    std::vector<std::unique_ptr<Field>> getOutput() override { return {}; }

private:
    bool checkInsertPermission(const Tuple* tuple) {
        if (!current_user) {
            if (audit_mode) {
                SecurityLogger::logAccessViolation("none", "No user context for insert operation");
            }
            return false;
        }

        bool has_permission = current_user->canAccess(current_table, Permission::WRITE, tuple->access_level);
        
        if (!has_permission && audit_mode) {
            SecurityLogger::logAccessDenied(
                current_user->username,
                tuple->access_level,
                "insert operation on table " + current_table
            );
        }

        return has_permission;
    }

    void logAuditInfo(const std::string& operation_status) {
        std::cout << "Insert Operation Audit:\n"
                  << "- Status: " << operation_status << "\n"
                  << "- Table: " << current_table << "\n"
                  << "- User: " << current_user->username << "\n";
    }
};

class DeleteOperator : public Operator {
private:
    BufferManager& bufferManager;
    size_t pageId;
    size_t tupleId;
    const User* current_user;
    std::string current_table;
    bool audit_mode;

public:
    DeleteOperator(BufferManager& manager, size_t pageId, size_t tupleId, User* user, 
                  const std::string& table = "default", bool enable_audit = false)
        : bufferManager(manager), pageId(pageId), tupleId(tupleId), 
          current_user(user), current_table(table), audit_mode(enable_audit) {}

    void open() override {}

    bool next() override {
        if (!checkUserContext()) {
            return false;
        }

        auto& page = bufferManager.getPage(pageId);
        if (!page) return false;

        Slot* slot_array = reinterpret_cast<Slot*>(page->page_data.get());
        if (!slot_array[tupleId].empty) {
            const char* tuple_data = page->page_data.get() + slot_array[tupleId].offset;
            std::istringstream iss(std::string(tuple_data, slot_array[tupleId].length));
            auto tuple = Tuple::deserialize(iss);

            if (!checkDeletePermission(tuple.get())) {
                return false;
            }

            page->deleteTuple(tupleId);
            bufferManager.flushPage(pageId);
            
            if (audit_mode) {
                logAuditInfo("successful delete");
            }
            return true;
        }

        return false;
    }

    void close() override {}
    std::vector<std::unique_ptr<Field>> getOutput() override { return {}; }

private:
    bool checkUserContext() {
        if (!current_user) {
            if (audit_mode) {
                SecurityLogger::logAccessViolation("none", "No user context for delete operation");
            }
            return false;
        }
        return true;
    }

    bool checkDeletePermission(const Tuple* tuple) {
        bool has_permission = current_user->canAccess(current_table, Permission::DELETE, tuple->access_level);
        
        if (!has_permission && audit_mode) {
            SecurityLogger::logAccessDenied(
                current_user->username,
                tuple->access_level,
                "delete operation on table " + current_table
            );
        }

        return has_permission;
    }

    void logAuditInfo(const std::string& operation_status) {
        std::cout << "Delete Operation Audit:\n"
                  << "- Status: " << operation_status << "\n"
                  << "- Table: " << current_table << "\n"
                  << "- User: " << current_user->username << "\n";
    }
};

class CrossTableOperation {
private:
    const User* user;
    std::vector<std::string> tables;
    Permission::JoinAccess join_type;

public:
    CrossTableOperation(const User* user, 
                       const std::vector<std::string>& tables,
                       Permission::JoinAccess join_type)
        : user(user), tables(tables), join_type(join_type) {}

    bool validateAccess() const {
        for (size_t i = 0; i < tables.size(); i++) {
            for (size_t j = i + 1; j < tables.size(); j++) {
                if (!checkJoinPermission(tables[i], tables[j])) {
                    return false;
                }
            }
        }
        return true;
    }

private:
    bool checkJoinPermission(const std::string& table1, const std::string& table2) const {
        for (const auto& role : user->roles) {
            for (const auto& perm : role.permissions) {
                if (perm.table_name == table1 && perm.canJoin(table2, join_type)) {
                    return true;
                }
            }
        }
        return false;
    }
};

class SecurityFilter {
public:
    struct FilterStats {
        size_t rows_filtered = 0;
        double selectivity = 1.0;
    };

    static std::unique_ptr<IPredicate> createSecurityPredicate(const User* user, const std::string& table) {
        auto complexPred = std::make_unique<ComplexPredicate>(ComplexPredicate::AND);
        
        auto accessLevelPred = std::make_unique<SimplePredicate>(
            SimplePredicate::Operand(0),
            SimplePredicate::Operand(std::make_unique<Field>(user->access_level)),
            SimplePredicate::ComparisonOperator::LE
        );
        
        bool hasTableAccess = false;
        for (const auto& role : user->roles) {
            for (const auto& perm : role.permissions) {
                if (perm.table_name == table && 
                    (perm.access_type == Permission::READ || perm.access_type == Permission::ALL)) {
                    hasTableAccess = true;
                    break;
                }
            }
            if (hasTableAccess) break;
        }

        if (!hasTableAccess) {
            auto falsePred = std::make_unique<SimplePredicate>(
                SimplePredicate::Operand(std::make_unique<Field>(1)),
                SimplePredicate::Operand(std::make_unique<Field>(0)),
                SimplePredicate::ComparisonOperator::EQ
            );
            complexPred->addPredicate(std::move(falsePred));
        }

        complexPred->addPredicate(std::move(accessLevelPred));
        return complexPred;
    }

    static FilterStats collectStats(const User* user, const std::string& table) {
        FilterStats stats;
        stats.selectivity = user->access_level / 100.0;
        return stats;
    }
};

class QueryOptimizer {
private:
    struct PlanStats {
        double row_count = 0;
        double selectivity = 1.0;
        double cost = 0.0;
        size_t cache_hits = 0;
    };

    struct PlanNode {
        Operator* op;
        PlanStats stats;
        std::vector<std::unique_ptr<PlanNode>> children;
    };

    const User* current_user;
    std::unordered_map<std::string, SecurityFilter::FilterStats> filter_stats;
    std::unordered_map<std::string, std::unique_ptr<IPredicate>> predicate_cache;
    std::unordered_map<std::string, PlanStats> table_stats;
    bool audit_mode;

public:
    QueryOptimizer(User* user, bool enable_audit = false) 
        : current_user(user), audit_mode(enable_audit) {}

    std::unique_ptr<Operator> optimizeQuery(
        std::unique_ptr<Operator> original_plan,
        const std::string& table) {
        
        if (audit_mode) {
            std::cout << "Starting query optimization for table: " << table << "\n";
        }
        initializeStats(table);
        auto security_pred = getSecurityPredicate(table);
        auto secured_plan = applySecurityFilter(std::move(original_plan), 
                                              table, 
                                              std::move(security_pred));
        auto optimized_plan = optimizePlan(std::move(secured_plan));

        if (audit_mode) {
            printOptimizationStats();
        }

        return optimized_plan;
    }

private:
    void initializeStats(const std::string& table) {
        filter_stats[table] = SecurityFilter::collectStats(current_user, table);
        
        PlanStats stats;
        stats.selectivity = filter_stats[table].selectivity;
        stats.row_count = estimateRowCount(table);
        table_stats[table] = stats;
    }

    double estimateRowCount(const std::string& table) {
        double base_count = 1000.0;
        double security_factor = current_user->access_level / 100.0;
        return base_count * security_factor;
    }

    std::unique_ptr<IPredicate> getSecurityPredicate(const std::string& table) {
        auto cache_it = predicate_cache.find(table);
        if (cache_it != predicate_cache.end()) {
            table_stats[table].cache_hits++;
            return cache_it->second->clone();
        }

        auto pred = SecurityFilter::createSecurityPredicate(current_user, table);
        predicate_cache[table] = pred->clone();
        return pred;
    }

    std::unique_ptr<Operator> applySecurityFilter(
        std::unique_ptr<Operator> plan,
        const std::string& table,
        std::unique_ptr<IPredicate> security_pred) {
        
        return std::make_unique<SelectOperator>(
            *plan,
            std::move(security_pred),
            const_cast<User*>(current_user),
            table,
            audit_mode
        );
    }

    std::unique_ptr<Operator> optimizePlan(std::unique_ptr<Operator> plan) {
        auto start_cost = estimateOperatorCost(plan.get());

        if (auto select = dynamic_cast<SelectOperator*>(plan.get())) {
            plan = optimizeSelect(std::move(plan));
        }
        auto final_cost = estimateOperatorCost(plan.get());
        if (audit_mode && final_cost < start_cost) {
            std::cout << "Optimization reduced cost from " << start_cost 
                     << " to " << final_cost << "\n";
        }

        return plan;
    }

    double estimateOperatorCost(const Operator* op) {
        if (auto select = dynamic_cast<const SelectOperator*>(op)) {
            return estimateSelectCost(select);
        } 
        else {
            return 1000.0;
        }
    }

    double estimateSelectCost(const SelectOperator* select) {
        double input_cost = estimateOperatorCost(select->getInput());
        double selectivity = filter_stats[select->getCurrentTable()].selectivity;
        return input_cost * selectivity;
    }

    std::unique_ptr<Operator> optimizeSelect(std::unique_ptr<Operator> plan) {
        auto select = dynamic_cast<SelectOperator*>(plan.get());
        auto combined_pred = combinePredicates(select);

        return std::make_unique<SelectOperator>(
            *select->getInput(),
            std::move(combined_pred),
            const_cast<User*>(current_user),
            select->getCurrentTable(),
            audit_mode
        );
    }


    std::unique_ptr<IPredicate> combinePredicates(SelectOperator* select) {
        auto complex_pred = std::make_unique<ComplexPredicate>(ComplexPredicate::AND);
        
        auto security_pred = getSecurityPredicate(select->getCurrentTable());
        complex_pred->addPredicate(std::move(security_pred));
        
        return complex_pred;
    }

    void printOptimizationStats() {
        std::cout << "\nOptimization Statistics:\n";
        for (const auto& [table, stats] : table_stats) {
            std::cout << "Table: " << table << "\n"
                     << "- Estimated rows: " << stats.row_count << "\n"
                     << "- Selectivity: " << stats.selectivity << "\n"
                     << "- Cache hits: " << stats.cache_hits << "\n";
        }
    }
};

class JoinOptimizer {
private:
    struct JoinStats {
        double cost;
        double selectivity;
        size_t result_size;
    };

    const User* current_user;
    std::unordered_map<std::string, JoinStats> join_stats_cache;

public:
    JoinOptimizer(User* user) : current_user(user) {}

    std::unique_ptr<Operator> optimizeJoin(
        std::unique_ptr<Operator> left_input,
        std::unique_ptr<Operator> right_input,
        const std::string& left_table,
        const std::string& right_table) {
        
        if (!validateJoinPermission(left_table, right_table)) {
            throw std::runtime_error("Join operation not permitted");
        }

        auto join_stats = estimateJoinStats(left_table, right_table);
        auto secured_left = applySecurityPredicates(std::move(left_input), left_table);
        auto secured_right = applySecurityPredicates(std::move(right_input), right_table);

        return createOptimizedJoin(
            std::move(secured_left),
            std::move(secured_right),
            join_stats
        );
    }

private:
    bool validateJoinPermission(const std::string& left_table, const std::string& right_table) {
        std::vector<std::string> tables = {left_table, right_table};
        CrossTableOperation op(current_user, tables, Permission::JoinAccess::INNER);
        return op.validateAccess();
    }

    JoinStats estimateJoinStats(const std::string& left_table, const std::string& right_table) {
        std::string join_key = left_table + "_" + right_table;

        auto it = join_stats_cache.find(join_key);
        if (it != join_stats_cache.end()) {
            return it->second;
        }

        JoinStats stats;
        stats.selectivity = estimateJoinSelectivity(left_table, right_table);
        stats.cost = estimateJoinCost(left_table, right_table);
        stats.result_size = estimateResultSize(left_table, right_table);

        join_stats_cache[join_key] = stats;
        return stats;
    }

    double estimateJoinSelectivity(const std::string& left_table, const std::string& right_table) {
        double security_factor = current_user->access_level / 100.0;
        return security_factor * 0.1;
    }

    double estimateJoinCost(const std::string& left_table, const std::string& right_table) {
        return 100.0;
    }

    size_t estimateResultSize(const std::string& left_table, const std::string& right_table) {
        return 1000;
    }

    std::unique_ptr<Operator> applySecurityPredicates(std::unique_ptr<Operator> input, const std::string& table) {
        auto security_pred = SecurityFilter::createSecurityPredicate(current_user, table);
        return std::make_unique<SelectOperator>(
            *input,
            std::move(security_pred),
            const_cast<User*>(current_user),
            table,
            true
        );
    }

    std::unique_ptr<Operator> createOptimizedJoin(
        std::unique_ptr<Operator> left,
        std::unique_ptr<Operator> right,
        const JoinStats& stats) {
        return std::make_unique<HashJoinOperator>(
            std::move(left),
            std::move(right),
            const_cast<User*>(current_user),
            true
        );
    }
};


class BuzzDB {
private:
    std::unordered_map<std::string, Role> roles;
    std::unordered_map<std::string, TablePermissions::TableSchema> table_schemas;
    std::unique_ptr<QueryOptimizer> optimizer;
    RoleManager& role_manager = RoleManager::getInstance();

public:
    HashIndex hash_index;
    BufferManager buffer_manager;
    std::unordered_map<std::string, User> users;
    User* current_user;
    size_t max_number_of_tuples = 5000;
    size_t tuple_insertion_attempt_counter = 0;

    BuzzDB() {
        initializeRoles();
        setupAdminUser();
        optimizer = std::make_unique<QueryOptimizer>(current_user);
    }

    void createRole(const std::string& role_name) {
        roles.emplace(role_name, Role(role_name));
    }

    void updateRolePermission(const std::string& role_name, 
                            const std::string& table,
                            Permission::AccessType new_type,
                            int new_level) {
        validateAdminAccess("update_role_permission");
        role_manager.updatePermission(role_name, table, new_type, new_level);
        logPermissionChange(role_name, table, new_level);
    }

    void setRoleInheritance(const std::string& child_role, 
                           const std::string& parent_role) {
        validateAdminAccess("set_role_inheritance");
        role_manager.inheritPermissions(child_role, parent_role);
        logRoleChange(child_role, parent_role);
    }
    
    void addPermissionToRole(const std::string& role_name, 
                           const std::string& table_name,
                           Permission::AccessType type,
                           int level) {
        validateAdminAccess("add_permission");
        auto it = roles.find(role_name);
        if (it != roles.end()) {
            it->second.addPermission(Permission(table_name, type, level));
            logPermissionChange(role_name, table_name, level);
        }
    }

    void grantJoinPermission(const std::string& role_name,
                            const std::string& from_table,
                            const std::string& to_table,
                            Permission::JoinAccess access) {
        validateAdminAccess("grant_join_permission");
        auto role_it = roles.find(role_name);
        if (role_it != roles.end()) {
            for (auto& perm : role_it->second.permissions) {
                if (perm.table_name == from_table) {
                    perm.addJoinPermission(to_table, access);
                    logJoinPermissionGrant(role_name, from_table, to_table);
                    break;
                }
            }
        }
    }

    void revokeRole(const std::string& username, const std::string& role_name) {
        validateAdminAccess("revoke_role");
        auto user_it = users.find(username);
        if (user_it != users.end()) {
            auto& user_roles = user_it->second.roles;
            user_roles.erase(
                std::remove_if(user_roles.begin(), user_roles.end(),
                    [&role_name](const Role& role) {
                        return role.role_name == role_name;
                    }
                ),
                user_roles.end()
            );
            logRoleRevocation(username, role_name);
        }
    }

    void addUser(const std::string& username, int access_level) {
        validateAdminAccess("add_user");
        users.emplace(username, User(username, access_level));
        assignDefaultRole(username, access_level);
        logUserCreation(username, access_level);
    }

    bool setCurrentUser(const std::string& username) {
        auto it = users.find(username);
        if (it != users.end()) {
            current_user = &it->second;
            optimizer = std::make_unique<QueryOptimizer>(current_user);
            logUserLogin(username);
            return true;
        }
        return false;
    }

    void insert(int key, int value, int access_level) {
        validateUserContext();
        validateInsertPermission(access_level);

        tuple_insertion_attempt_counter++;
        auto newTuple = createTuple(key, value, access_level);
        performInsert(std::move(newTuple));
        logDataModification("insert", key);
    }

    void executeQueries() {
        validateUserContext();

        std::vector<std::string> test_queries = {
            "SUM{1} GROUP BY {1} WHERE {1} > 2 and {1} < 6"
        };

        for (const auto& query : test_queries) {
            auto components = parseQuery(query);
            auto plan = createQueryPlan(components);
            auto optimized_plan = optimizer->optimizeQuery(std::move(plan), "default");
            executeOptimizedPlan(std::move(optimized_plan));
            logQueryExecution(query);
        }
    }

    bool validateJoinOperation(const std::vector<std::string>& tables,
                             Permission::JoinAccess join_type) {
        if (!current_user) return false;
        CrossTableOperation op(current_user, tables, join_type);
        return op.validateAccess();
    }

private:
    void validateAdminAccess(const std::string& operation) {
        if (!current_user || current_user->access_level < 100) {
            throw std::runtime_error("Admin access required for " + operation);
        }
    }

    void validateUserContext() {
        if (!current_user) {
            throw std::runtime_error("No user set!");
        }
    }

    void validateInsertPermission(int access_level) {
        if (!current_user->canAccess("default", Permission::WRITE, access_level)) {
            SecurityLogger::logAccessDenied(current_user->username, 
                                          access_level, 
                                          "insert operation");
            throw std::runtime_error("Insufficient privileges");
        }
    }

    void logPermissionChange(const std::string& role, const std::string& table, int level) {
        SecurityLogger::getAuditTrail().logEvent(
            current_user->username,
            AuditTrail::EventType::PERMISSION_CHANGE,
            table,
            "permission_update",
            level,
            true,
            "Role: " + role
        );
    }

    void logRoleChange(const std::string& child, const std::string& parent) {
        SecurityLogger::getAuditTrail().logEvent(
            current_user->username,
            AuditTrail::EventType::ROLE_CHANGE,
            "N/A",
            "inheritance_set",
            0,
            true,
            "Child: " + child + ", Parent: " + parent
        );
    }

    void logJoinPermissionGrant(const std::string& role, 
                               const std::string& from_table,
                               const std::string& to_table) {
        SecurityLogger::getAuditTrail().logEvent(
            current_user->username,
            AuditTrail::EventType::PERMISSION_CHANGE,
            from_table,
            "join_permission_grant",
            0,
            true,
            "Role: " + role + ", To: " + to_table
        );
    }

    void logRoleRevocation(const std::string& username, const std::string& role) {
        SecurityLogger::getAuditTrail().logEvent(
            current_user->username,
            AuditTrail::EventType::ROLE_CHANGE,
            "N/A",
            "role_revocation",
            0,
            true,
            "User: " + username + ", Role: " + role
        );
    }

    void logUserCreation(const std::string& username, int access_level) {
        SecurityLogger::getAuditTrail().logEvent(
            current_user->username,
            AuditTrail::EventType::ACCESS_ATTEMPT,
            "N/A",
            "user_creation",
            access_level,
            true,
            "New user: " + username
        );
    }

    void logUserLogin(const std::string& username) {
        SecurityLogger::getAuditTrail().logEvent(
            username,
            AuditTrail::EventType::LOGIN_ATTEMPT,
            "N/A",
            "login",
            0,
            true
        );
    }

    void logDataModification(const std::string& operation, int key) {
        SecurityLogger::getAuditTrail().logEvent(
            current_user->username,
            AuditTrail::EventType::DATA_MODIFICATION,
            "default",
            operation,
            0,
            true,
            "Key: " + std::to_string(key)
        );
    }

    void logQueryExecution(const std::string& query) {
        SecurityLogger::getAuditTrail().logEvent(
            current_user->username,
            AuditTrail::EventType::QUERY_EXECUTION,
            "default",
            "query",
            0,
            true,
            "Query: " + query
        );
    }

    void initializeRoles() {
        createRole("admin_role");
        addPermissionToRole("admin_role", "default", Permission::ALL, 100);
        
        createRole("regular_role");
        addPermissionToRole("regular_role", "default", Permission::ALL, 50);
        
        createRole("restricted_role");
        addPermissionToRole("restricted_role", "default", Permission::READ, 25);
    }

    void setupAdminUser() {
        users.emplace("admin", User("admin", 100));
        assignRoleToUser("admin", "admin_role");
        setCurrentUser("admin");
    }

    // Keep existing helper methods...
    void assignDefaultRole(const std::string& username, int access_level) {
        if (access_level >= 100) {
            assignRoleToUser(username, "admin_role");
        } else if (access_level >= 50) {
            assignRoleToUser(username, "regular_role");
        } else {
            assignRoleToUser(username, "restricted_role");
        }
    }

    std::unique_ptr<Tuple> createTuple(int key, int value, int access_level) {
        auto newTuple = std::make_unique<Tuple>(access_level);
        newTuple->addField(std::make_unique<Field>(key));
        newTuple->addField(std::make_unique<Field>(value));
        newTuple->addField(std::make_unique<Field>(132.04f));
        newTuple->addField(std::make_unique<Field>("buzzdb"));
        return newTuple;
    }

    void performInsert(std::unique_ptr<Tuple> newTuple) {
        InsertOperator insertOp(buffer_manager, current_user);
        insertOp.setTupleToInsert(std::move(newTuple));
        bool status = insertOp.next();
        assert(status == true);

        if (tuple_insertion_attempt_counter % 10 != 0) {
            DeleteOperator delOp(buffer_manager, 0, 0, current_user);
            delOp.next();
        }
    }

    std::unique_ptr<Operator> createQueryPlan(const QueryComponents& components) {
        auto scanOp = std::make_unique<ScanOperator>(buffer_manager, current_user);
        
        if (!components.whereCondition) {
            return scanOp;
        }

        auto pred = std::make_unique<SimplePredicate>(
            SimplePredicate::Operand(components.whereAttributeIndex),
            SimplePredicate::Operand(std::make_unique<Field>(components.lowerBound)),
            SimplePredicate::ComparisonOperator::GT
        );

        return std::make_unique<SelectOperator>(
            *scanOp,
            std::move(pred),
            current_user
        );
    }

    void executeOptimizedPlan(std::unique_ptr<Operator> plan) {
        plan->open();
        while (plan->next()) {
            const auto& output = plan->getOutput();
            for (const auto& field : output) {
                field->print();
                std::cout << " ";
            }
            std::cout << "\n";
        }
        plan->close();
    }
};

void test(BuzzDB& db) {
    // Test 1
    TableManager tableManager;
    try {
        tableManager.createTable("test_table", {"col1", "col2", "col3"});
        std::cout << "Test 1 Passed: Table 'test_table' created successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test 1 Failed: " << e.what() << std::endl;
    }

    // Test 2
    try {
        tableManager.createTable("test_table", {"col1", "col2", "col3"});
        std::cerr << "Test 2 Failed: Duplicate table creation allowed." << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Test 2 Passed: " << e.what() << std::endl;
    }

    // Test 3
    try {
        db.setCurrentUser("admin");
        std::cout << "Test 3 Passed: Admin user set up successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test 3 Failed: " << e.what() << std::endl;
    }

    // Test 5
    try {
        db.updateRolePermission("regular_role", "default", Permission::READ, 50);
        std::cout << "Test 5 Passed: Role permission updated successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test 5 Failed: " << e.what() << std::endl;
    }

    // Test 6
    try {
        db.insert(1, 100, 50);
        db.insert(2, 200, 50);
        std::cout << "Test 6 Passed: Data inserted successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test 6 Failed: " << e.what() << std::endl;
    }

    // Test 7
    try {
        db.setCurrentUser("user1");
        db.executeQueries();
        std::cout << "Test 7 Passed: Queries executed successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test 7 Failed: " << e.what() << std::endl;
    }

    // Test 8
    try {
        db.setCurrentUser("user1");
        db.insert(3, 300, 100); // This should fail due to insufficient access level
        std::cerr << "Test 8 Failed: Access violation not detected." << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Test 8 Passed: " << e.what() << std::endl;
    }

    // Test 9
    try {
        db.updateRolePermission("regular_role", "default", Permission::ALL, 100);
        db.setCurrentUser("user1");
        db.insert(3, 300, 100); // This should now succeed
        std::cout << "Test 9 Passed: User role updated successfully, and insert succeeded." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test 9 Failed: " << e.what() << std::endl;
    }

    // Test 10
    try {
        db.setCurrentUser("admin");
        db.executeQueries();
        std::cout << "Test 10 Passed: Query plan optimized successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test 10 Failed: " << e.what() << std::endl;
    }
}


int main() {
    TableManager tableManager;

    tableManager.createTable("default", {"id", "value", "float_val", "string_val"});
    tableManager.createTable("user_data", {"user_id", "username", "email"});
    tableManager.displayTables();

    BuzzDB db;
    test(db);
    return 0;
}

// int main() {
//     BuzzDB db;

//     std::cout << "\n=== Setting up users ===\n";
//     db.addUser("user1", 50);  // mid-level access
//     db.addUser("user2", 25);  // low-level access
    
//     // Test inserting data with different access levels as admin
//     std::cout << "\n=== Testing Admin Insert (Level 100) ===\n";
//     db.setCurrentUser("admin");
//     try {
//         db.insert(1, 100, 75);  // high security data
//         std::cout << "Admin: Inserted tuple with level 75\n";
//         db.insert(2, 200, 50);  // medium security data
//         std::cout << "Admin: Inserted tuple with level 50\n";
//         db.insert(3, 300, 25);  // low security data
//         std::cout << "Admin: Inserted tuple with level 25\n";
//         db.insert(4, 400, 0);   // public data
//         std::cout << "Admin: Inserted tuple with level 0\n";
//     } catch (const std::runtime_error& e) {
//         std::cout << "Error: " << e.what() << std::endl;
//     }

//     // Test user1 (level 50)
//     std::cout << "\n=== Testing User1 (Level 50) ===\n";
//     db.setCurrentUser("user1");
//     try {
//         db.insert(5, 500, 75);  // Should fail - too high
//         std::cout << "User1: Inserted tuple with level 75\n";
//     } catch (const std::runtime_error& e) {
//         std::cout << "Expected error for User1: " << e.what() << std::endl;
//     }

//     try {
//         db.insert(6, 600, 50);  // Should work
//         std::cout << "User1: Inserted tuple with level 50\n";
//         db.insert(7, 700, 25);  // Should work
//         std::cout << "User1: Inserted tuple with level 25\n";
//     } catch (const std::runtime_error& e) {
//         std::cout << "Error: " << e.what() << std::endl;
//     }

//     // Test user2 (level 25)
//     std::cout << "\n=== Testing User2 (Level 25) ===\n";
//     db.setCurrentUser("user2");
//     try {
//         db.insert(8, 800, 50);  // Should fail
//         std::cout << "User2: Inserted tuple with level 50\n";
//     } catch (const std::runtime_error& e) {
//         std::cout << "Expected error for User2: " << e.what() << std::endl;
//     }

//     try {
//         db.insert(9, 900, 25);  // Should work
//         std::cout << "User2: Inserted tuple with level 25\n";
//         db.insert(10, 1000, 0); // Should work
//         std::cout << "User2: Inserted tuple with level 0\n";
//     } catch (const std::runtime_error& e) {
//         std::cout << "Error: " << e.what() << std::endl;
//     }

//     // Test queries with different access levels
//     std::cout << "\n=== Query Test with Admin ===\n";
//     db.setCurrentUser("admin");
//     db.executeQueries();  // Should see all data

//     std::cout << "\n=== Query Test with User1 ===\n";
//     db.setCurrentUser("user1");
//     db.executeQueries();  // Should only see level ≤ 50

//     std::cout << "\n=== Query Test with User2 ===\n";
//     db.setCurrentUser("user2");
//     db.executeQueries();  // Should only see level ≤ 25

//     // Test deletion permissions
//     std::cout << "\n=== Testing Delete Permissions ===\n";
    
//     // Admin delete test
//     db.setCurrentUser("admin");
//     try {
//         DeleteOperator delOp(db.buffer_manager, 0, 0, db.current_user);
//         if (delOp.next()) {
//             std::cout << "Admin: Successfully deleted high security tuple\n";
//         }
//     } catch (const std::runtime_error& e) {
//         std::cout << "Error: " << e.what() << std::endl;
//     }

//     // User2 delete test
//     db.setCurrentUser("user2");
//     try {
//         DeleteOperator delOp(db.buffer_manager, 0, 1, db.current_user);
//         if (!delOp.next()) {
//             std::cout << "User2: Correctly denied deletion of higher security tuple\n";
//         }
//     } catch (const std::runtime_error& e) {
//         std::cout << "Expected error for User2 deletion: " << e.what() << std::endl;
//     }

//     // Test bulk data loading with admin
//     std::cout << "\n=== Testing Bulk Load with Admin ===\n";
//     db.setCurrentUser("admin");
//     std::ifstream inputFile("output.txt");
//     if (!inputFile) {
//         std::cerr << "Unable to open file" << std::endl;
//         return 1;
//     }

//     int field1, field2;
//     int i = 0;
//     while (inputFile >> field1 >> field2) {
//         if(i++ % 10000 == 0) {
//             int access_level = (field1 <= 5) ? 25 : 50;
//             db.insert(field1, field2, access_level);
//         }
//     }

//     std::cout << "\n=== Final Query Tests ===\n";
//     auto start = std::chrono::high_resolution_clock::now();

//     // Test final queries with different users
//     std::cout << "Admin Query Results:\n";
//     db.setCurrentUser("admin");
//     db.executeQueries();

//     std::cout << "\nUser1 Query Results:\n";
//     db.setCurrentUser("user1");
//     db.executeQueries();

//     std::cout << "\nUser2 Query Results:\n";
//     db.setCurrentUser("user2");
//     db.executeQueries();

//     auto end = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double> elapsed = end - start;
//     std::cout << "\nElapsed time: " << 
//         std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count() 
//         << " microseconds" << std::endl;

//     return 0;
// }
