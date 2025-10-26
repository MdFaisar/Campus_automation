// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ComplaintContract
 * @dev Smart contract for anonymous complaint submission system
 * @author Anonymous Complaint System Team
 */
contract ComplaintContract {
    
    // Struct to store complaint data
    struct Complaint {
        string hashedStudentId;     // Hashed student ID for anonymity
        string complaintHash;       // Hash of complaint content (stored off-chain)
        string facultyId;           // Faculty member ID
        uint256 timestamp;          // Submission timestamp
        bool isActive;              // Whether complaint is active
    }
    
    // Mapping from complaint ID to complaint data
    mapping(uint256 => Complaint) public complaints;
    
    // Mapping from faculty ID to array of complaint IDs
    mapping(string => uint256[]) public facultyComplaints;
    
    // Mapping to track daily submissions per hashed student ID
    mapping(string => mapping(uint256 => bool)) public dailySubmissions;
    
    // Counter for complaint IDs
    uint256 public complaintCounter;
    
    // Contract owner
    address public owner;
    
    // Events
    event ComplaintSubmitted(
        uint256 indexed complaintId,
        string hashedStudentId,
        string facultyId,
        uint256 timestamp
    );
    
    event ComplaintDeactivated(
        uint256 indexed complaintId,
        address indexed deactivatedBy
    );
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier validComplaintId(uint256 _complaintId) {
        require(_complaintId > 0 && _complaintId <= complaintCounter, "Invalid complaint ID");
        _;
    }
    
    /**
     * @dev Constructor sets the contract owner
     */
    constructor() {
        owner = msg.sender;
        complaintCounter = 0;
    }
    
    /**
     * @dev Submit a new complaint
     * @param _hashedStudentId Hashed student ID for anonymity
     * @param _complaintHash Hash of the complaint content
     * @param _facultyId Faculty member ID to route the complaint
     * @return complaintId The ID of the submitted complaint
     */
    function submitComplaint(
        string memory _hashedStudentId,
        string memory _complaintHash,
        string memory _facultyId
    ) external returns (uint256) {
        // Validate inputs
        require(bytes(_hashedStudentId).length > 0, "Hashed student ID cannot be empty");
        require(bytes(_complaintHash).length > 0, "Complaint hash cannot be empty");
        require(bytes(_facultyId).length > 0, "Faculty ID cannot be empty");
        
        // Check daily limit
        require(checkDailyLimit(_hashedStudentId), "Daily complaint limit exceeded");
        
        // Get current day (timestamp / 86400 to get day number)
        uint256 currentDay = block.timestamp / 86400;
        
        // Mark that this student has submitted today
        dailySubmissions[_hashedStudentId][currentDay] = true;
        
        // Increment complaint counter
        complaintCounter++;
        
        // Create new complaint
        complaints[complaintCounter] = Complaint({
            hashedStudentId: _hashedStudentId,
            complaintHash: _complaintHash,
            facultyId: _facultyId,
            timestamp: block.timestamp,
            isActive: true
        });
        
        // Add to faculty's complaint list
        facultyComplaints[_facultyId].push(complaintCounter);
        
        // Emit event
        emit ComplaintSubmitted(
            complaintCounter,
            _hashedStudentId,
            _facultyId,
            block.timestamp
        );
        
        return complaintCounter;
    }
    
    /**
     * @dev Check if a student can submit a complaint today
     * @param _hashedStudentId Hashed student ID
     * @return bool True if student can submit, false otherwise
     */
    function checkDailyLimit(string memory _hashedStudentId) public view returns (bool) {
        uint256 currentDay = block.timestamp / 86400;
        return !dailySubmissions[_hashedStudentId][currentDay];
    }
    
    /**
     * @dev Get all complaint IDs for a specific faculty member
     * @param _facultyId Faculty member ID
     * @return uint256[] Array of complaint IDs
     */
    function getComplaintsByFaculty(string memory _facultyId) external view returns (uint256[] memory) {
        return facultyComplaints[_facultyId];
    }
    
    /**
     * @dev Get complaint details by ID
     * @param _complaintId Complaint ID
     * @return hashedStudentId The hashed student ID
     * @return complaintHash The complaint content hash
     * @return facultyId The faculty member ID
     * @return timestamp The submission timestamp
     * @return isActive Whether the complaint is active
     */
    function getComplaint(uint256 _complaintId) external view validComplaintId(_complaintId) returns (
        string memory hashedStudentId,
        string memory complaintHash,
        string memory facultyId,
        uint256 timestamp,
        bool isActive
    ) {
        Complaint memory complaint = complaints[_complaintId];
        return (
            complaint.hashedStudentId,
            complaint.complaintHash,
            complaint.facultyId,
            complaint.timestamp,
            complaint.isActive
        );
    }
    
    /**
     * @dev Get active complaints for a faculty member
     * @param _facultyId Faculty member ID
     * @return uint256[] Array of active complaint IDs
     */
    function getActiveComplaintsByFaculty(string memory _facultyId) external view returns (uint256[] memory) {
        uint256[] memory allComplaints = facultyComplaints[_facultyId];
        uint256 activeCount = 0;
        
        // Count active complaints
        for (uint256 i = 0; i < allComplaints.length; i++) {
            if (complaints[allComplaints[i]].isActive) {
                activeCount++;
            }
        }
        
        // Create array of active complaints
        uint256[] memory activeComplaints = new uint256[](activeCount);
        uint256 index = 0;
        
        for (uint256 i = 0; i < allComplaints.length; i++) {
            if (complaints[allComplaints[i]].isActive) {
                activeComplaints[index] = allComplaints[i];
                index++;
            }
        }
        
        return activeComplaints;
    }
    
    /**
     * @dev Deactivate a complaint (admin function)
     * @param _complaintId Complaint ID to deactivate
     */
    function deactivateComplaint(uint256 _complaintId) external onlyOwner validComplaintId(_complaintId) {
        require(complaints[_complaintId].isActive, "Complaint is already inactive");
        
        complaints[_complaintId].isActive = false;
        
        emit ComplaintDeactivated(_complaintId, msg.sender);
    }
    
    /**
     * @dev Get total number of complaints
     * @return uint256 Total complaint count
     */
    function getTotalComplaints() external view returns (uint256) {
        return complaintCounter;
    }
    
    /**
     * @dev Get contract statistics
     * @return totalComplaints Total number of complaints
     * @return activeComplaints Number of active complaints
     */
    function getContractStats() external view returns (uint256 totalComplaints, uint256 activeComplaints) {
        totalComplaints = complaintCounter;
        activeComplaints = 0;
        
        for (uint256 i = 1; i <= complaintCounter; i++) {
            if (complaints[i].isActive) {
                activeComplaints++;
            }
        }
        
        return (totalComplaints, activeComplaints);
    }
    
    /**
     * @dev Transfer ownership of the contract
     * @param _newOwner Address of the new owner
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "New owner cannot be zero address");
        owner = _newOwner;
    }
}
