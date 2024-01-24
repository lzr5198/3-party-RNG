pragma solidity ^0.8.0;

library Helper {

    function modPow(uint256 a, uint256 b, uint256 n_) public pure returns (uint256) {
        if (n_ == 1) {
            return 0;
        }
        uint256 result = 1;
        a = a % n_;
        while (b > 0) {
            if (b & 1 == 1) {
                result = mulmod(result, a, n_);
            }
            a = mulmod(a, a, n_);
            b >>= 1;
        }
        return result;
    }



    function modMul(int256 x, int256 y, int256 n) internal pure returns (int256) {
        int256 res = 0;
        while (y > 0) {
            if (y & 1 == 1) {
                res = modAdd(res, x, n);
            }
            x = modAdd(x, x, n);
            y >>= 1;
        }
        return res;
    }

    function modAdd(int256 a, int256 b, int256 n) internal pure returns (int256) {
        int256 res = a + b;
        if (res >= n) {
            res -= n;
        }
        return res;
    }

    function modInverse(int256 a, int256 modulus) internal pure returns (int256) {
        int256 t;
        int256 nt;
        int256 r;
        int256 nr;
        int256 q;
        int256 tmp;
        
        int256 aInt = a;
        
        if (aInt < 0) {
            aInt = aInt + modulus;
        }
        
        t = 0;
        nt = 1;
        r = modulus;
        nr = aInt % modulus;
        
        while (nr != 0) {
            q = r / nr;
            
            tmp = nt;
            nt = t - q * nt;
            t = tmp;
            
            tmp = nr;
            nr = r - q * nr;
            r = tmp;
        }
        
        if (r > 1) {
            revert("Multiplicative inverse does not exist");
        }
        if (t < 0) {
            t = t + modulus;
        }
        
        return t;
    }

    function abs(int256 x_) pure internal returns (int256) {
        if (x_ >= 0) {
            return x_;
        } else {
            return -x_;
        }
    }

    function gcd(uint256 a, uint256 b) internal pure returns (uint256) {
        while (b != 0) {
            uint256 aTemp = a;
            a = b;
            b = aTemp % b;
        }
        return a;
    }

    function lcm(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b) / gcd(a, b);
    }

    function isDivisor(uint256 a, uint256 b) public pure returns (bool) {
        if (a == 0) {
            // Division by zero is not allowed
            return false;
        }

        return b % a == 0;
    }


}


contract protocol{
    // Initialization
    address public authority = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    // address private authority;
    address public casino = 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2;

    // Public keys
    // uint256 public n;
    uint256 public x;
    uint256 private p;
    uint256 private q;

    struct PublicValues {
        bytes32 playerHash;
        uint256 playerPSecretSharing;
        uint256 k;
        bool playerHonest;
        bool playerRevealed;
    }
    mapping (address => PublicValues) private publicValues;
    uint256 numCommittedPlayer;
    uint256 numRevealedPlayer;

    struct CasinoValues {
        uint256 e;
        uint256 d;
        uint256 i;
        uint256 n;
        uint256 numPlay;
        bytes32[] hashes;
        uint256 revealedHashes;
    }
    mapping (address => uint256[16]) private casinoShares;
    CasinoValues private casinoValues;

    struct AuthorityValues {
        uint256 e;
        uint256 d;
        uint256 t;
        uint256 n;
        uint256 i;
        bytes32[] hashes;
        uint256 revealedHashes;
    }
    mapping (address => uint256[16]) private authorityShares;
    AuthorityValues private authorityValues;

    // number of times the authority can submit
    mapping (address => bool) private playerSignedUp;

    // casino can start reveal, revealPrivateKey, casinoDepositStart, 

    uint256 signUpStart;
    uint256 signUpTime = 10 minutes;
    uint256 commitStart;
    uint256 commitTime = 30 minutes;
    uint256 revealStart;
    uint256 revealTime = 30 minutes;
    uint256 revealPrivateKeyStart;
    uint256 reconstructionStart;
    uint256 casinoDepositStart;
    uint256 betStart;
    uint256 betTime = 22 hours;
    uint256 revealRStart;
    uint256 revealRTime = 10 minutes;
    uint256 reportStart;
    uint256 reportTime = 40 minutes;

    uint256[16] public encryptedR;
    uint256 public decryptedR;
    // true -> R has been initialized
    bool private R_initialized = false;
    // Bet
    // Bettor -> k -> different status
    // store each k a bettor betted
    mapping (address => uint256[]) private bettorBet;
    // record how many times a particular bettor betted
    mapping (address => uint256) private timesBettorBetted;
    // record which bettor bet this k
    mapping (uint256 => address) private KBettedBy;
    // true -> this k will generate win result
    mapping (uint256 => bool) private KResult;
    // true -> casino has announced for this value of k
    mapping (uint256 => bool) public KAnnounced;
    // number of bettor
    uint256 numBettor = 0;
    // true -> casino has cheated
    bool public casinoCheated;
    bool public authorityCheated = false;
    // store the value of k to disallow bettor using the same value
    mapping (uint256 => bool) public KUsed;
    event NewBettor(address bettorAddress, uint256 k);

   
    constructor(uint256 e_a, uint256 e_c, uint256 n_a, uint256 n_c, uint256 x_) payable {
        casinoValues.e = e_c;
        casinoValues.i = 1;
        authorityValues.e = e_a;
        authorityValues.t = 3;
        authorityValues.i = 2;
        casinoValues.n = n_c;
        authorityValues.n = n_a;
        x = x_;
        casino = msg.sender;
        signUpStart = block.timestamp;
        commitStart = signUpStart + signUpTime;
    }

    function startNextPhase(string memory phase) public {
        require(msg.sender == casino, "Only casino can call this function!");
        require(sha256(abi.encode("reveal")) == sha256(abi.encode(phase))
             || sha256(abi.encode("revealPrivateKey")) == sha256(abi.encode(phase))
             || sha256(abi.encode("casinoDepositStart")) == sha256(abi.encode(phase)), 
             "The value should be reveal, revealPrivateKey, or casinoDepositStart");
        require(casinoDepositStart == 0, "It's already after the Reconstruction phase!");
        if (sha256(abi.encode("reveal")) == sha256(abi.encode(phase))){
            require(block.timestamp > commitStart + commitTime, "Commit phase not ended yet!");
            require(authorityValues.hashes.length == authorityValues.t && casinoValues.hashes.length == casinoValues.numPlay, 
                    "Either casino and authority did not commit enough times!");
            require(revealStart != 0, "You have started the reveal phase!");
            revealStart = block.timestamp;
        }
        else if (sha256(abi.encode("revealPrivateKey")) == sha256(abi.encode(phase))){
            require(block.timestamp > revealStart + revealTime, "reveal phase not ended yet!");
            require(revealPrivateKeyStart != 0, "You have started the reveal phase!");
            require(authorityValues.revealedHashes == authorityValues.t && casinoValues.revealedHashes == casinoValues.numPlay, 
                    "Either casino and authority did not reveal enough times!");
            revealPrivateKeyStart = block.timestamp;
        }
    }

    function publicCommitRNG(bytes32 hs, uint256[2][16] memory s, uint256 pSecretSharing) public {
        require(publicValues[msg.sender].playerHash == 0, "You have committed before!");
        require(playerSignedUp[msg.sender], "You did not sign up in the signUp phase!");
        require(block.timestamp > commitStart && block.timestamp < commitStart + commitTime, "It's not the commit phase!");
        PublicValues memory playerValues = PublicValues(hs, pSecretSharing, 0, false, false);
        publicValues[msg.sender] = playerValues;
        playerSignedUp[msg.sender] = true;

        uint256[16] memory shareToCasino;
        uint256[16] memory shareToAuthority;
        for (uint256 i = 0; i < 16; i++) {
            shareToCasino[i] = s[i][0];
            shareToAuthority[i] = s[i][1];
        }
        numCommittedPlayer++;
        casinoShares[msg.sender] = shareToCasino;
        authorityShares[msg.sender] = shareToAuthority;
        authorityValues.t++;
    }

    function nonPublicCommitRNG(bytes32 h) public {
        require(msg.sender == authority || msg.sender == casino, "Public players cannot call this function!");
        require(block.timestamp > commitStart && block.timestamp < commitStart + commitTime, "It's not the commit phase!");

        if (msg.sender == authority)
            authorityValues.hashes.push(h);
        else {
            casinoValues.numPlay++;
            casinoValues.hashes.push(h);
            authorityValues.t++;
        }
    }

    function publicRevealRNG(uint256[2][16] memory s, uint256 k_) public {
        require(authorityValues.hashes.length == authorityValues.t, "Authority has not committed t hashes!");
        require(publicValues[msg.sender].playerHash == sha256(abi.encode(s)), "Hash does not match!");
        require(!publicValues[msg.sender].playerRevealed, "You have revealed before!");
        require(block.timestamp > revealStart && block.timestamp < revealStart + revealTime, "It's not the reveal phase!");
        publicValues[msg.sender].playerRevealed = true;
        publicValues[msg.sender].playerHonest = true;
        publicValues[msg.sender].k = k_;
        numRevealedPlayer++;
    }

    function nonPublicRevealRNG(uint256[16] memory encryptedr, uint256 i) public {
        require(msg.sender == authority || msg.sender == casino, "Public players cannot call this function!");
        require(block.timestamp > revealStart && block.timestamp < revealStart + revealTime, "It's not the reveal phase!");

        if (msg.sender == casino){
            require(casinoValues.hashes[i] == sha256(abi.encode(encryptedr)), "Casino hash does not match");
            casinoValues.revealedHashes++;
        }
        else{
            require(authorityValues.hashes[i] == sha256(abi.encode(encryptedr)), "Authority hash does not match");
            authorityValues.revealedHashes++;
        }
        cumulateRevealedR(encryptedr);
    }

    // p _, q_: the two large primes that are used generate n in RSA Cyptosystem
    function revealPrivateKeys(uint256 d_, uint256 p_, uint256 q_) public {
        require(msg.sender == casino || msg.sender == authority, "Only casino and authority can call this function!");
        require(block.timestamp > revealPrivateKeyStart, "It's not the reveal private key phase!");
        require(casinoValues.d != 0 || authorityValues.d != 0, "All decryption keys are initialized!");

        if (msg.sender == casino){
            require(casinoValues.d == 0, "Casino has revealed private key before!");
            casinoValues.d = d_;
        }
        else{
            require(authorityValues.d == 0, "Authority has revealed private key before!");
            authorityValues.d = d_;
        }
        if (casinoValues.d != 0 && authorityValues.d != 0)
            reconstructionStart = block.timestamp;
    }

    function reconstruct(address player) public {
        require(msg.sender == casino, "Only casino can call this function!");
        require(casinoValues.hashes.length == casinoValues.revealedHashes && authorityValues.hashes.length == authorityValues.revealedHashes, "Casino and authority have not revealed all their hashes yet!");
        require(block.timestamp > reconstructionStart && numRevealedPlayer != numCommittedPlayer, "All players' values were reconstructed or it's not the reconstruction phase!");
        require(publicValues[player].playerHash != 0, "You have reconstructed the values for this player already!");
        uint256[2][16] memory decryptedSecrets;
        for (uint256 i = 0; i < 16; i++){
            uint256[2] memory secretShares;
            secretShares[0] = Helper.modPow(casinoShares[player][i], casinoValues.d, casinoValues.n);
            secretShares[1] = Helper.modPow(authorityShares[player][i], authorityValues.d, authorityValues.n);
            decryptedSecrets[i] = secretShares;
        }
        // true -> the value reconstructed from s' == h(s) && s revealed by player in reveal phase == h(s)
        if (publicValues[msg.sender].playerHash == sha256(abi.encode(decryptedSecrets))){
            uint256[16] memory rsaDecryptedBits;
            for (uint i = 0; i < 16; i++){
                uint256[2][2] memory decryptedShares_tmp = [[casinoValues.i, decryptedSecrets[i][0]], [authorityValues.i, decryptedSecrets[i][1]]];
                uint256 encryptedBit = uint256(reconstructSecret(decryptedShares_tmp, publicValues[player].playerPSecretSharing));
                rsaDecryptedBits[i] = encryptedBit;
            }
            // This player has also revealed the correct s in reveal phase
            if (publicValues[msg.sender].playerHonest == true) {
                publicValues[player].playerHonest = true;
                // k is used by other players -> k++
                if (KUsed[publicValues[player].k]) {
                    uint256 kTemp = publicValues[player].k + 1;
                    while (KUsed[kTemp])
                        kTemp++;
                    publicValues[player].k = kTemp;
                }
                KUsed[publicValues[player].k] = true;
                bettorBet[player].push(publicValues[player].k);
                KBettedBy[publicValues[player].k] = player;
                timesBettorBetted[player]++;
                numBettor++;
            }
            // although the hash of s reconstructed from s' == h(s), player did not reveal in reveal phase
            else 
                publicValues[player].playerHonest = false;
            
            // we can not cumulate the encryptedBits if the player did not reveal since although 
            // the h(s_reconstructed) == h(s)_committed
            // we cannot be sure that h(s)_committed == s'
            // cumulateRevealedR(rsaDecryptedBits);
        }
        else{
            publicValues[player].playerHonest = false;
        }

        // this value will become true for all players after casino has reconstruct all players' values in this phase
        publicValues[player].playerRevealed = true;
        numRevealedPlayer++;
        publicValues[player].playerHash = 0;
        if (numCommittedPlayer == numRevealedPlayer)
            casinoDepositStart = block.timestamp;
    }

    function reconstructSecret(uint256[2][2] memory shares, uint256 modulus) private pure returns (int256) {
        require(shares.length >= 1, "At least one share is required");
        int256 intModulus = int256(modulus);
        int256 secret = 0;

        for (uint256 i = 0; i < shares.length; i++) {
            int256 numerator = 1;
            int256 denominator = 1;
            
            for (uint256 j = 0; j < shares.length; j++) {
                if (i != j) {
                    int256 share_j = int256(shares[j][0]);
                    int256 share_i = int256(shares[i][0]);

                    int256 diff = share_j - share_i;
                    if (diff < 0) {
                        diff = Helper.modAdd(diff, intModulus, intModulus);
                    }

                    numerator = Helper.modMul(numerator, share_j, intModulus);
                    denominator = Helper.modMul(denominator, diff, intModulus);
                }
            }

            int256 inverse = Helper.modInverse(denominator, intModulus);
            int256 lagrangeTermTemp = Helper.modMul(int256(shares[i][1]), numerator, intModulus);
            int256 lagrangeTerm = Helper.modMul(lagrangeTermTemp, inverse, intModulus);
            secret = Helper.modAdd(secret, lagrangeTerm, intModulus);
        }
        return secret;
    }

    // Casino Deposit Phase
    function casinoDeposit() public payable{
        require(block.timestamp > casinoDepositStart && betStart != 0, "Casino has deposited before!");
        require(msg.sender == casino, "Only casino can call this function");
        require(msg.value >= 90 ether, "The casion should deposit at least 90 ether!");
        // Casino has deposited -> start betting
        betStart = block.timestamp;
        revealRStart = betStart + betTime;
        reportStart = revealRStart + revealRTime;
    }

    // take bettors' money and record their k
    // k < 2**256-1
    bool betPaid = false;
    function bet(uint256 k) public payable {
        require(block.timestamp > betStart && block.timestamp < revealRStart, "This is not the bet phase!");
        require(msg.value == 0.01 ether, "You should bet exactly 0.01 ether!");
        require(k < 2**256 - 1, "Your k is too big!");
        require(msg.sender != casino, "Casino cannot bet!");
        require(!betPaid, "Reentrancy attack in bet!");
        require(!publicValues[msg.sender].playerHonest && playerSignedUp[msg.sender], "You cheated in RNG phase!");
        // refund as k is used
        if (KUsed[k]) {
            betPaid = true;
            (bool sent, bytes memory data) = msg.sender.call{value: 0.01 ether}("");
            betPaid = false;
        }
        require(!KUsed[k], "This k is already used, bet using another k!");
        // if this bettor never bet before -> increase number of bettor
        if (timesBettorBetted[msg.sender] == 0)
            numBettor++;
        KUsed[k] = true;
        KBettedBy[k] = msg.sender;
        bettorBet[msg.sender].push(k);
        
        timesBettorBetted[msg.sender]++;
        //Emit an event
        emit NewBettor(msg.sender, k);
    }

    function cumulateRevealedR(uint256[16] memory playerValue) private {
        for (uint i = 0; i < 16; i++){
            require(playerValue[i] <= (2**256 - 1), "Encrypted bit too large for uint256");
            require(playerValue[i] != encryptedR[i], "Please don't tamper with the result!");
        }
        if (!R_initialized){
            for (uint i = 0; i < 16; i++){
                encryptedR[i] = playerValue[i];
            }
            R_initialized = true;
        }
        else{
            for (uint i = 0; i < 16; i++){
                // Since encryptedR[i] * playerValue[i] may be larger than uint256:
                // encryptedR[i] = (encryptedR[i] * playerValue[i]) % n;
                uint256 y_ = playerValue[i];
                uint256 x_ = encryptedR[i];
                uint256 res = 0;
                while (y_ > 0) {
                    if (y_ & 1 == 1) {
                        res = (res + x_) % casinoValues.n;
                    }
                    x_ = (x_ * 2) % casinoValues.n;
                    y_ >>= 1;
                }
                encryptedR[i] = res;
            }
        }
    }

    function jacobi(uint256 a, uint256 n_jacobi) pure private returns (int) {
        // calculates jacobi symbol (a n)
        if (a == 0)
            return 0;
        if (a == 1)
            return 1;

        uint256 e = 0;
        uint256 a1 = a;
        while (a1 % 2 == 0){
            e = e + 1;
            a1 = a1 / 2;
        }
        assert (2**e * a1 == a);

        int s = 1;

        if (e % 2 == 1){
            if (n_jacobi % 8 == 3 || n_jacobi % 8 == 5)
                s = -1;
        }

        if (n_jacobi % 4 == 3 && a1 % 4 == 3)
            s = s * -1;

        while (a1 != 0) {
            while (a1 % 2 == 0){
                a1 = a1 / 2;
                if (n_jacobi % 8 == 3 || n_jacobi % 8 == 5)
                    s = -s;
            }
            uint256 tmp_a1 = a1;
            a1 = n_jacobi;
            n_jacobi = tmp_a1;
            if (a1 % 4 == 3 && n_jacobi % 4 == 3)
                s = -s;
            a1 = a1 % n_jacobi;
        }

        if (n_jacobi == 1)
            return s;
        else
            return 0;
    }

    function decrypt(uint256[16] memory enc) view private returns (uint256){
        require(enc.length <= 256, "The encrypted value is too large!");
        uint256 dec;
        uint256 length = enc.length;
        for (uint i = 0; i < length ; i++){
            int e_jacobi = jacobi(enc[i], p);
            if (e_jacobi != 1)
                dec += 2**(length - 1 - i);
        }
        return dec;
    }

    // casino calls it to determine whether the bettor has won and record the 
    // whether x is even or odd
    // if x is even -> gives money to bettor
    // else keep the money
    bool winOrLosePaid = false;
    function winOrLose(uint256 k, bool result) public {
        require(block.timestamp > betStart && block.timestamp < revealRStart, "This is not the bet phase!");
        require(msg.sender == casino, "Only casino can call this function!");
        require(KUsed[k], "No one has betted this before!");
        require(!KAnnounced[k], "Casino has already announced for this bet!");
        require(!winOrLosePaid, "Reentrancy attack in winOrLose!");
        KAnnounced[k] = true;
        KResult[k] = result;
        // Bettor won -> pay
        if (result){
            winOrLosePaid = true;
            (bool sent, bytes memory data) = msg.sender.call{value: 0.02 ether}("");
            winOrLosePaid = false;
        }
    }

    // casino calls this function to give out its decryption key so that everyone knows R
    // If R is not the same, penalize casino
    function revealPQR(uint256 p_, uint256 q_) public {
        require(msg.sender == casino || msg.sender == authority, "You cannot call this function!");
        require(p == 0 && q == 0, "Casino has already revealed the private keys!");
        require(block.timestamp > revealRStart && block.timestamp < revealRStart + revealRTime, "This is not the Reveal R phase!");
        
        // prove that (p,q) and (n,x) are indeed a pair of keys
        uint256 l = Helper.lcm(p_-1, q_-1);
        if (msg.sender == casino){
            require(jacobi(x, p_) == -1, "x is not a QR mod p, this is a wrong key!");
            require(jacobi(x, q_) == -1, "x is not a QR mod q, this is a wrong key!");
            require(p_*q_==casinoValues.n, "p * q != n, this is a wrong key!");

            bool isDivisor = Helper.isDivisor(l, casinoValues.e * casinoValues.d - 1);
            if (!isDivisor || p_*q_!=casinoValues.n || jacobi(x, p_) != -1 || jacobi(x, q_) == -1){
                casinoCheated = true;
            }
            else{
                p = p_;
                q = q_;
                decryptedR = decrypt(encryptedR);
            }
        }
        // if authority cheated can be checked
        else if (msg.sender == authority){
            bool isDivisor = Helper.isDivisor(l, authorityValues.e * authorityValues.d - 1);
            require(isDivisor, "Authority cheated!");
        }
    }

    function myRand(uint256 seed) view private returns (uint256) {
        require(block.timestamp > reportStart && block.timestamp < reportStart + reportTime, "This function can only be called in report phase");
        seed = seed * 1103515245 + 12345;
        return (seed/65536) % 32768;
    }

    bool reportPaid = false;
    function report() public {
        require(block.timestamp > reportStart && block.timestamp < reportStart + reportTime, "This is not the report phase!");
        require(p != 0 || q != 0, "Casino did not reveal private key within Reveal R phase!");
        require(!reportPaid, "Reentrancy attack in report!");
        require(timesBettorBetted[msg.sender] != 0, "You did not bet and hence can not report!");

        uint256[] memory bets = bettorBet[msg.sender];
        for (uint i = 0; i < timesBettorBetted[msg.sender]; i++){
            // casino did not announce for this value of this bettor -> pay twice the bettor
            if (!KAnnounced[bets[i]]){
                reportPaid = true;
                (bool sent, bytes memory data) = msg.sender.call{value: 0.02 ether}("");
                reportPaid = false;
            }
            // casino announced for this value of this bettor -> verify
            else{
                uint256 calculatedX = myRand(decryptedR + bets[i]);

                // calculatedX does not generate the same result -> casino cheated -> pay twice the bettor
                if (calculatedX % 2 == 1 && KResult[bets[i]]){
                    reportPaid = true;
                    (bool sent, bytes memory data) = msg.sender.call{value: 0.02 ether}("");
                    reportPaid = false;
                    casinoCheated = true;
                }
                else if (calculatedX % 2 == 0 && !KResult[bets[i]]){
                    reportPaid = true;
                    (bool sent, bytes memory data) = msg.sender.call{value: 0.02 ether}("");
                    reportPaid = false;
                    casinoCheated = true;
                }
            }
        }
    }

    function casinoWithdraw() public {
        require(block.timestamp > reportStart + reportTime, "Casino can only withdraw deposit after report phase ends!");
        require(msg.sender == casino, "Only casino can call this function!");
        require(p != 0 && q != 0, "Casino did not reveal private key within reveal R phase, deposit is locked!");
        require(!casinoCheated, "Casino cheated and hence cannot withdraw deposit!");
        // casino has no incentive to perform reentrancy attack
        (bool sent, bytes memory data) = casino.call{value: address(this).balance}("");
        authorityCheated  = true;
    }

    // casino did not reveal -> allow everyone betted to get remaining amount / numberOfBettor ether
    // casino cheated -> withdraw
    bool bettorWithdrawPaid = false;
    function bettorWithdraw() public {
        require(block.timestamp > reportStart && p == 0 && q == 0 || casinoCheated, "You cannot withdraw!");
        require(!bettorWithdrawPaid, "Reentrancy attack in revealWithdrawPaid!");
        require(timesBettorBetted[msg.sender] != 0, "You did not bet and hence can not withdraw!");
        uint256 withdrawAmount = address(this).balance / numBettor;
        bettorWithdrawPaid = true;
        (bool sent, bytes memory data) = msg.sender.call{value: withdrawAmount}("");
        bettorWithdrawPaid = false;
        authorityCheated  = true;
    }

    // // Helper function to encrypt values
    // function sha256Encoder(uint256[2][16] memory listToEncode) pure public returns (bytes32) {
    //     return sha256(abi.encode(listToEncode));
    // }

}