import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import { randomBytes } from 'crypto';

const prisma = new PrismaClient();

// Tamil Nadu Location Data (Shared globally - no candidateId)
const LOCATION_DATA = [
  {
    taluk: 'Coimbatore North',
    district: 'Coimbatore',
    villages: [
      { name: 'Vilankurichi', wards: ['1', '2', '3', '4', '5'] },
      { name: 'Thudiyalur', wards: ['1', '2', '3', '4'] },
      { name: 'Kalapatti', wards: ['1', '2', '3', '4', '5', '6'] },
      { name: 'Saravanampatti', wards: ['1', '2', '3', '4', '5'] },
    ],
  },
  {
    taluk: 'Coimbatore South',
    district: 'Coimbatore',
    villages: [
      { name: 'Singanallur', wards: ['1', '2', '3', '4', '5', '6'] },
      { name: 'Peelamedu', wards: ['1', '2', '3', '4'] },
      { name: 'Ganapathy', wards: ['1', '2', '3', '4', '5'] },
      { name: 'Ramanathapuram', wards: ['1', '2', '3'] },
    ],
  },
  {
    taluk: 'Pollachi',
    district: 'Coimbatore',
    villages: [
      { name: 'Pollachi Town', wards: ['1', '2', '3', '4', '5', '6'] },
      { name: 'Kinathukadavu', wards: ['1', '2', '3', '4'] },
      { name: 'Negamam', wards: ['1', '2', '3'] },
      { name: 'Zamin Uthukuli', wards: ['1', '2', '3', '4'] },
    ],
  },
];

function generateSecurePassword() {
  return randomBytes(24).toString('base64url');
}

/**
 * Seed shared location data (global - no candidateId).
 * This data is shared across all candidates.
 */
async function seedSharedLocations() {
  console.log('Seeding shared location data...');
  
  for (const talukData of LOCATION_DATA) {
    const district = await prisma.district.upsert({
      where: { name: talukData.district },
      update: {},
      create: { name: talukData.district },
    });

    // Upsert Taluk (shared globally)
    const taluk = await prisma.taluk.upsert({
      where: {
        districtId_name: {
          districtId: district.id,
          name: talukData.taluk,
        },
      },
      update: {},
      create: {
        name: talukData.taluk,
        districtId: district.id,
      },
    });

    // Create Villages and Wards
    for (const villageData of talukData.villages) {
      const village = await prisma.village.upsert({
        where: {
          talukId_name: {
            talukId: taluk.id,
            name: villageData.name,
          },
        },
        update: {},
        create: {
          name: villageData.name,
          talukId: taluk.id,
        },
      });

      // Create Wards for this village
      for (const wardNumber of villageData.wards) {
        await prisma.ward.upsert({
          where: {
            villageId_wardNumber: {
              villageId: village.id,
              wardNumber,
            },
          },
          update: {},
          create: {
            wardNumber,
            villageId: village.id,
          },
        });
      }
    }
  }
  
  console.log('Shared locations seeded successfully!');
}

/**
 * Seed zones for a specific candidate (tenant-scoped).
 */
async function seedZonesForCandidate(candidateId: string) {
  console.log('Seeding zones for candidate...');
  
  // Check if zones already exist for this candidate
  const existingZones = await prisma.zone.count({ where: { candidateId } });
  if (existingZones > 0) {
    console.log('Zones already exist for this candidate');
    return;
  }
  
  await prisma.zone.createMany({
    data: [
      { type: 'RED', name: 'Red Zone', colorHex: '#ef4444', candidateId },
      { type: 'GREEN', name: 'Green Zone', colorHex: '#22c55e', candidateId },
      { type: 'ORANGE', name: 'Orange Zone', colorHex: '#f97316', candidateId },
    ],
  });
  
  console.log('Zones seeded successfully!');
}

async function main() {
  console.log('Starting seed...');
  console.log('');

  // Step 1: Seed shared location data (global)
  await seedSharedLocations();
  console.log('');

  // Step 2: Create demo candidate and admin user
  const defaultEmail = process.env.DEFAULT_ADMIN_EMAIL?.trim() || 'admin@example.com';
  const defaultUsername = process.env.DEFAULT_ADMIN_USERNAME?.trim() || 'admin';
  const configuredPassword = process.env.DEFAULT_ADMIN_PASSWORD?.trim();
  const generatedPassword = configuredPassword ? null : generateSecurePassword();
  const adminPassword = configuredPassword ?? generatedPassword!;

  // Check if candidate already exists
  const existingCandidate = await prisma.candidate.findUnique({
    where: { email: defaultEmail },
  });

  if (existingCandidate) {
    console.log(`Candidate with email ${defaultEmail} already exists. Skipping candidate creation.`);
    console.log('');
    console.log('='.repeat(50));
    console.log('SEED COMPLETED');
    console.log('='.repeat(50));
    console.log('No new credentials were generated. Use existing account credentials.');
    return;
  }

  // Create sample Candidate (LOCAL_BODY election type)
  const candidate = await prisma.candidate.create({
    data: {
      fullName: 'Demo Candidate',
      phone: '+91 9876543210',
      email: defaultEmail,
      electionType: 'LOCAL_BODY',
      contestingFor: 'Councillor',
      district: 'Coimbatore',
      constituency: 'Coimbatore North',
      partyName: 'Independent',
      bio: 'Demo candidate account for testing purposes.',
    },
  });

  console.log(`Created candidate: ${candidate.fullName} (${candidate.id})`);

  // Create ADMIN user for this candidate
  const passwordHash = await argon2.hash(adminPassword);
  const adminUser = await prisma.user.create({
    data: {
      username: defaultUsername,
      email: defaultEmail,
      passwordHash,
      role: 'ADMIN',
      candidateId: candidate.id,
      fullName: candidate.fullName,
      phone: candidate.phone,
    },
  });

  console.log(`Created admin user: ${adminUser.username} (${adminUser.id})`);

  // Seed zones for this candidate (tenant-scoped)
  await seedZonesForCandidate(candidate.id);

  console.log('');
  console.log('='.repeat(50));
  console.log('SEED COMPLETED SUCCESSFULLY');
  console.log('='.repeat(50));
  console.log('');
  console.log('Login credentials:');
  console.log(`  Email:    ${defaultEmail}`);
  if (configuredPassword) {
    console.log('  Password: [configured via DEFAULT_ADMIN_PASSWORD]');
  } else if (generatedPassword) {
    console.log(`  Password: ${generatedPassword}`);
    console.log('  IMPORTANT: Store this password securely and rotate it after first login.');
  }
  console.log('');
  console.log('NOTE: Location data (Taluk, Village, Ward) is SHARED globally.');
  console.log('      Zones are scoped to individual candidates.');
  console.log('');
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (error) => {
    console.error(error);
    await prisma.$disconnect();
    process.exit(1);
  });
